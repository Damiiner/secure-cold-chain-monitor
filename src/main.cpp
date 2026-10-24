#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <time.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_MPU6050.h>
#include <Adafruit_Sensor.h>
#include "mbedtls/md.h"

// ---------- Pins ----------
#define PIN_TEMP_IN 4
#define PIN_TEMP_OUT 2 // keep the pin you ended up using
#define PIN_DOOR 41
#define PIN_BUTTON 40
#define PIN_BUZZER 39
#define PIN_LIGHT 1
#define PIN_LED_G 10
#define PIN_LED_Y 11
#define PIN_LED_R 12
#define PIN_SDA 8
#define PIN_SCL 9
#define PIN_SDA2 47
#define PIN_SCL2 21

// ---------- Network settings ----------
const char *MQTT_HOST = "broker.hivemq.com"; // keep the broker that works for you
const uint16_t MQTT_PORT = 1883;
const char *MQTT_TOPIC = "coldchain/9w7tzbxemrsf/CC-0001/records";
const unsigned long TEST_OFFLINE_MS = 0; // 30000 to re-run the backlog demo

// ---------- Limits ----------
const float T_LOW = 2.0;
const float T_HIGH = 8.0;
const float T_MARGIN = 0.5;
const float MAX_JUMP = 3.0;
const int LIGHT_OPEN_THRESH = 2000;
const float SHOCK_THRESH = 5.0;

// ---------- AI settings (demo-scaled) ----------
const float HORIZON_MIN = 30.0; // warn if a limit will be crossed within this time
const float SLOPE_MIN = 0.05;   // degC/min: below this the trend is "flat"
const float RAPID_SLOPE = 6.0;  // degC/min: demo value (real box: about 1.0)
const char *AI_TAG = "rules-v1";

// ---------- Security ----------
const char *DEVICE_ID = "CC-0001";
const uint8_t DEV_KEY[] = "demo-device-key"; // production: secure element
uint8_t prevHash[32] = {0};
uint32_t seqNo = 0;

// ---------- Objects ----------
OneWire owIn(PIN_TEMP_IN), owOut(PIN_TEMP_OUT);
DallasTemperature sensorIn(&owIn), sensorOut(&owOut);
Adafruit_SSD1306 display(128, 64, &Wire, -1);
Adafruit_MPU6050 mpu;
WiFiClient net;
PubSubClient mqtt(net);

enum State
{
  ST_OK,
  ST_WARNING,
  ST_EXCURSION,
  ST_FAULT
};

float tIn = 0, tOut = 0, lastTIn = NAN;
bool doorOpen = false, lightOpen = false, shock = false, implausible = false;
bool oledOk = false, mpuOk = false;
int lightRaw = 0;
float accelDev = 0;
unsigned long lastSample = 0;
bool lastButton = HIGH;

// ---------- AI: trend, forecast, MKT ----------
#define HIST_N 10
float histT[HIST_N], histV[HIST_N];
int histCount = 0, histHead = 0;
float slopePerMin = 0; // degC per minute (least-squares fit)
float etaMin = -1;     // minutes until a limit is crossed, -1 = none
double mktSum = 0, mktW = 0;
double mkt = NAN;

void histClear()
{
  histCount = 0;
  histHead = 0;
}

void histAdd(float tSec, float v)
{
  histT[histHead] = tSec;
  histV[histHead] = v;
  histHead = (histHead + 1) % HIST_N;
  if (histCount < HIST_N)
    histCount++;
}

void updateTrend()
{
  slopePerMin = 0;
  etaMin = -1;
  if (histCount < 4)
    return; // need a few points

  int n = histCount;
  int start = (histHead - n + HIST_N) % HIST_N;
  float x0 = histT[start];
  double sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (int i = 0; i < n; i++)
  {
    int idx = (start + i) % HIST_N;
    double x = (histT[idx] - x0) / 60.0; // minutes
    double y = histV[idx];
    sx += x;
    sy += y;
    sxx += x * x;
    sxy += x * y;
  }
  double den = n * sxx - sx * sx;
  if (fabs(den) < 1e-9)
    return;
  slopePerMin = (float)((n * sxy - sx * sy) / den);

  float t = histV[(histHead - 1 + HIST_N) % HIST_N];
  if (slopePerMin > SLOPE_MIN && t < T_HIGH)
    etaMin = (T_HIGH - t) / slopePerMin;
  else if (slopePerMin < -SLOPE_MIN && t > T_LOW)
    etaMin = (t - T_LOW) / (-slopePerMin);
}

// Mean Kinetic Temperature, dH/R = 10000 K, time-weighted
void updateMkt(float tC, double dtSec)
{
  double tk = tC + 273.15;
  mktSum += dtSec * exp(-10000.0 / tk);
  mktW += dtSec;
  if (mktW > 0 && mktSum > 0)
    mkt = (10000.0 / (-log(mktSum / mktW))) - 273.15;
}

void updateAI()
{
  static unsigned long lastMkt = 0;
  unsigned long now = millis();
  double dt = lastMkt ? (now - lastMkt) / 1000.0 : 3.0;
  lastMkt = now;

  bool valid = (tIn > -100.0 && tIn < 84.0);
  if (implausible)
    histClear(); // an impossible jump breaks the trend
  if (valid)
  {
    histAdd(now / 1000.0f, tIn);
    updateMkt(tIn, dt);
  }
  updateTrend();
}

// ---------- Store-and-forward queue ----------
#define QUEUE_SIZE 40
#define REC_MAX 420
char queueBuf[QUEUE_SIZE][REC_MAX];
int qHead = 0, qCount = 0;
uint32_t droppedRecords = 0;

void enqueue(const char *json)
{
  if (qCount == QUEUE_SIZE)
  {
    qHead = (qHead + 1) % QUEUE_SIZE;
    qCount--;
    droppedRecords++;
  }
  int tail = (qHead + qCount) % QUEUE_SIZE;
  strncpy(queueBuf[tail], json, REC_MAX - 1);
  queueBuf[tail][REC_MAX - 1] = 0;
  qCount++;
}

void flushQueue()
{
  while (qCount > 0 && mqtt.connected())
  {
    if (!mqtt.publish(MQTT_TOPIC, queueBuf[qHead]))
      break;
    qHead = (qHead + 1) % QUEUE_SIZE;
    qCount--;
    mqtt.loop();
  }
}

// ---------- Network ----------
unsigned long lastNetTry = 0;
bool ntpStarted = false, wifiWasUp = false;

unsigned long nowTs()
{
  time_t t = time(nullptr);
  if (t > 1700000000)
    return (unsigned long)t;
  return millis() / 1000;
}

void serviceNetwork()
{
  if (millis() < TEST_OFFLINE_MS)
    return;

  if (WiFi.status() != WL_CONNECTED)
  {
    wifiWasUp = false;
    if (millis() - lastNetTry > 10000)
    {
      lastNetTry = millis();
      WiFi.begin("Wokwi-GUEST", "", 6);
    }
    return;
  }
  if (!wifiWasUp)
  {
    wifiWasUp = true;
    Serial.println("WiFi connected");
  }

  if (!ntpStarted)
  {
    configTime(0, 0, "pool.ntp.org", "time.google.com");
    ntpStarted = true;
  }

  if (!mqtt.connected())
  {
    if (millis() - lastNetTry > 5000)
    {
      lastNetTry = millis();
      String id = String("cc-0001-") + String((uint32_t)esp_random(), HEX);
      if (mqtt.connect(id.c_str()))
        Serial.println("MQTT connected");
      else
        Serial.printf("MQTT failed rc=%d\r\n", mqtt.state());
    }
    return;
  }
  mqtt.loop();
  flushQueue();
}

// ---------- Records: hash chain + signature ----------
void toHex(const uint8_t *in, size_t n, char *out)
{
  const char *h = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
  {
    out[i * 2] = h[in[i] >> 4];
    out[i * 2 + 1] = h[in[i] & 0x0F];
  }
  out[n * 2] = 0;
}

void chainAndSign(const char *body, uint8_t hash[32], uint8_t sig[32])
{
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, prevHash, 32);
  mbedtls_md_update(&ctx, (const unsigned char *)body, strlen(body));
  mbedtls_md_finish(&ctx, hash);
  mbedtls_md_free(&ctx);

  mbedtls_md_hmac(info, DEV_KEY, sizeof(DEV_KEY) - 1, hash, 32, sig);
}

// body: id|seq|ts|t_in|t_out|door|lux|shock|state|cause|eta_min|mkt|ai_tag
void emitRecord(const char *stateStr, const char *cause)
{
  char body[160];
  snprintf(body, sizeof(body), "%s|%lu|%lu|%.2f|%.2f|%d|%d|%.2f|%s|%s|%.0f|%.2f|%s",
           DEVICE_ID, (unsigned long)seqNo, nowTs(),
           tIn, tOut, doorOpen ? 1 : 0, lightRaw, accelDev, stateStr, cause,
           etaMin >= 0 ? etaMin : -1.0f, isnan(mkt) ? 0.0 : mkt, AI_TAG);

  uint8_t hash[32], sig[32];
  char prevHex[65], hashHex[65], sigHex[65];

  toHex(prevHash, 32, prevHex);
  chainAndSign(body, hash, sig);
  toHex(hash, 32, hashHex);
  toHex(sig, 32, sigHex);
  memcpy(prevHash, hash, 32);
  seqNo++;

  char json[400];
  snprintf(json, sizeof(json),
           "{\"body\":\"%s\",\"prev\":\"%s\",\"hash\":\"%s\",\"sig\":\"%s\"}",
           body, prevHex, hashHex, sigHex);

  Serial.printf("REC %s\r\n", json);
  enqueue(json);
}

// ---------- Logic ----------
State evaluate(float t)
{
  if (t < -100.0 || t > 84.0)
    return ST_FAULT;
  if (t < T_LOW || t > T_HIGH)
    return ST_EXCURSION;
  if (t < T_LOW + T_MARGIN || t > T_HIGH - T_MARGIN)
    return ST_WARNING;
  if (etaMin >= 0 && etaMin <= HORIZON_MIN)
    return ST_WARNING; // forecast breach
  return ST_OK;
}

const char *stateName(State s)
{
  switch (s)
  {
  case ST_OK:
    return "OK";
  case ST_WARNING:
    return "WARNING";
  case ST_EXCURSION:
    return "EXCURSION";
  default:
    return "FAULT";
  }
}

// Rule-based cause classifier (first match wins)
const char *classify(State s)
{
  if (s == ST_FAULT)
    return "sensor_fault";
  if (implausible)
    return "implausible";
  if (shock)
    return "handling_shock";
  if (doorOpen)
    return "door_open";
  if (slopePerMin >= RAPID_SLOPE)
    return "rapid_warming";
  if (slopePerMin >= SLOPE_MIN)
    return (tOut > tIn + 2.0) ? "ice_pack_depleted" : "temp_rising";
  if (slopePerMin <= -SLOPE_MIN && tIn < T_LOW + 2.0)
    return "freeze_risk";
  if (s != ST_OK)
    return (slopePerMin <= -SLOPE_MIN) ? "recovering" : "out_of_range";
  return "none";
}

unsigned long intervalFor(State s)
{
  switch (s)
  {
  case ST_OK:
    return 3000;
  case ST_WARNING:
    return 2000;
  default:
    return 1000;
  }
}

void setLeds(State s)
{
  digitalWrite(PIN_LED_G, s == ST_OK);
  digitalWrite(PIN_LED_Y, s == ST_WARNING || s == ST_FAULT);
  digitalWrite(PIN_LED_R, s == ST_EXCURSION);
}

void readSensors()
{
  sensorIn.requestTemperatures();
  sensorOut.requestTemperatures();
  tIn = sensorIn.getTempCByIndex(0);
  tOut = sensorOut.getTempCByIndex(0);

  doorOpen = (digitalRead(PIN_DOOR) == LOW);
  lightRaw = analogRead(PIN_LIGHT);
  lightOpen = (lightRaw > LIGHT_OPEN_THRESH);

  shock = false;
  if (mpuOk)
  {
    sensors_event_t a, g, temp;
    mpu.getEvent(&a, &g, &temp);
    float mag = sqrt(a.acceleration.x * a.acceleration.x +
                     a.acceleration.y * a.acceleration.y +
                     a.acceleration.z * a.acceleration.z);
    accelDev = fabs(mag - 9.81);
    shock = (accelDev > SHOCK_THRESH);
  }

  implausible = (!isnan(lastTIn) && fabs(tIn - lastTIn) > MAX_JUMP);
  lastTIn = tIn;
}

void showOled(State s, const char *cause)
{
  if (!oledOk)
    return;
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.print("COLD CHAIN MONITOR");
  display.setCursor(110, 0);
  display.print(mqtt.connected() ? "ON" : "--");

  display.setTextSize(2);
  display.setCursor(0, 10);
  if (s == ST_FAULT)
    display.print("-- C");
  else
  {
    display.print(tIn, 1);
    display.print(" C");
  }

  display.setTextSize(1);
  display.setCursor(0, 28);
  display.print("Out:");
  display.print(tOut, 1);
  display.print(" MKT:");
  display.print(isnan(mkt) ? 0.0 : mkt, 1);

  display.setCursor(0, 38);
  display.print("Why:");
  display.print(cause);

  display.setCursor(0, 48);
  display.printf("%+.2f C/m", slopePerMin);
  if (etaMin >= 0 && etaMin <= 999)
    display.printf(" ->%dm", (int)(etaMin + 0.5));

  display.setCursor(0, 56);
  display.print(stateName(s));
  display.print(" #");
  display.print(seqNo);
  display.print(" Q");
  display.print(qCount);
  display.display();
}

void setup()
{
  Serial.begin(115200);
  pinMode(PIN_LED_G, OUTPUT);
  pinMode(PIN_LED_Y, OUTPUT);
  pinMode(PIN_LED_R, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_DOOR, INPUT_PULLUP);
  pinMode(PIN_BUTTON, INPUT_PULLUP);

  Wire.begin(PIN_SDA, PIN_SCL);
  oledOk = display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  if (!oledOk)
    Serial.println("OLED not found (check SDA/SCL on 8/9)");

  Wire1.begin(PIN_SDA2, PIN_SCL2);
  mpuOk = mpu.begin(0x68, &Wire1);
  if (!mpuOk)
    Serial.println("MPU6050 not found (check SDA/SCL on 47/21)");

  sensorIn.begin();
  sensorOut.begin();

  WiFi.mode(WIFI_STA);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(15);
  mqtt.setKeepAlive(30);

  Serial.println("Cold chain monitor started");
}

void loop()
{
  serviceNetwork();

  bool btn = digitalRead(PIN_BUTTON);
  if (lastButton == HIGH && btn == LOW)
  {
    tone(PIN_BUZZER, 1500, 100);
    emitRecord("HANDOVER", "custody");
  }
  lastButton = btn;

  static State s = ST_OK;
  if (millis() - lastSample < intervalFor(s))
    return;
  lastSample = millis();

  readSensors();
  updateAI();
  s = evaluate(tIn);
  const char *cause = classify(s);

  setLeds(s);
  if (s == ST_EXCURSION)
    tone(PIN_BUZZER, 2000, 200);
  showOled(s, cause);

  emitRecord(stateName(s), cause);
}