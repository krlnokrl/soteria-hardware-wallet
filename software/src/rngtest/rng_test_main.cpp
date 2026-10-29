// RNG test firmware (env:rngtest_*), built in place of main.cpp.
//
// Measures RNGpin() (src/wallet.cpp) on the board: its output exactly as
// generateWallet() sees it before the sha256, and the raw pool bits before
// RNGpin()'s XOR whitening. Results are graded BAD / OK / GOOD / GREAT and
// printed on USB serial; 'b' / 'B' stream the bytes for offline tools
// (test/tools/rng_capture.py). Send '?' for the command list.
#include <Arduino.h>
#include <math.h>
#include "wallet.h"

enum Grade { BAD, OK, GOOD, GREAT };
static const char *const GRADE_NAME[] = {"BAD", "OK", "GOOD", "GREAT"};

static uint32_t s_sampleBytes = 4096;
static Grade s_worst;

/* ------------------------------------------------------------------ */
/* Raw source                                                          */
/* ------------------------------------------------------------------ */

// One iteration of RNGpin()'s inner loop, with every noise source kept
// apart. KEEP IN SYNC with RNGpin() in src/wallet.cpp.
struct RawSample {
  uint8_t bit;                        // the bit RNGpin() shifts into its pool
  uint8_t init, red, count, jitter;   // LSB of each blended source
  uint16_t waits;                     // analogRead(0) polls until it changed
};

static RawSample rawSample() {
  RawSample s;
  uint32_t t1 = SysTick->VAL;

  int init = analogRead(0);
  int red = analogRead(1) & 0x01;
  uint16_t count = 0;

  while (analogRead(0) == init) {
    ++count;
    if (count > 4096) break;
  }

  uint32_t timingJitter = t1 ^ SysTick->VAL;

  s.bit = (init ^ red ^ count ^ timingJitter) & 0x01;
  s.init = init & 1;
  s.red = red;
  s.count = count & 1;
  s.jitter = timingJitter & 1;
  s.waits = count;
  return s;
}

// The 32-bit pool RNGpin() whitens into one output byte (first sample in
// the MSB).
static uint32_t rawPool() {
  uint32_t pool = 0;
  for (unsigned i = 0; i < 32; ++i) pool = (pool << 1) | rawSample().bit;
  return pool;
}

/* ------------------------------------------------------------------ */
/* Statistics (streaming, so the sample size is not limited by RAM)    */
/* ------------------------------------------------------------------ */

struct ByteStats {
  uint32_t n;              // bytes seen
  uint32_t hist[256];
  uint32_t posOnes[8];     // ones per bit position (bit 0 = LSB)
  uint32_t flips;          // adjacent bits that differ, MSB-first bit stream
  uint32_t run, longestRun;
  int lastBit;
  uint8_t first, last;
  uint64_t sum, sumSq, sumLag;

  void reset() {
    memset(this, 0, sizeof(*this));
    lastBit = -1;
  }

  void add(uint8_t b) {
    hist[b]++;
    for (int i = 7; i >= 0; --i) {
      int bit = (b >> i) & 1;
      posOnes[i] += bit;
      if (bit == lastBit) {
        ++run;
      } else {
        if (lastBit >= 0) ++flips;
        run = 1;
      }
      if (run > longestRun) longestRun = run;
      lastBit = bit;
    }
    if (n == 0) first = b;
    else sumLag += (uint32_t)last * b;
    sum += b;
    sumSq += (uint32_t)b * b;
    last = b;
    ++n;
  }

  uint32_t ones() const {
    uint32_t s = 0;
    for (int i = 0; i < 8; ++i) s += posOnes[i];
    return s;
  }
};

static ByteStats s_stats;

// NIST SP 800-90B most-common-value estimate (6.3.1), bits per symbol.
static double mcvMinEntropy(double maxCount, double n) {
  double p = maxCount / n;
  double pu = p + 2.576 * sqrt(p * (1 - p) / (n - 1));
  if (pu > 1) pu = 1;
  return -log2(pu);
}

// Hypothesis tests: a perfect source gives a uniform p, so a single p
// cannot tell GOOD from GREAT; small p is evidence of a defect.
static Grade gradeP(double p) {
  if (p < 1e-4) return BAD;
  if (p < 0.01) return OK;
  return GOOD;
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static void printPad(const char *s, int width) {
  Serial.print(s);
  for (int i = strlen(s); i < width; ++i) Serial.print(' ');
}

static void beginRow(Grade g, const char *name) {
  if (g < s_worst) s_worst = g;
  Serial.print("  [");
  printPad(GRADE_NAME[g], 5);
  Serial.print("] ");
  printPad(name, 27);
}

static void beginInfo(const char *name) {
  Serial.print("  [info ] ");
  printPad(name, 27);
}

static void printP(double p) {
  Serial.print("p=");
  if (p >= 0.001) {
    Serial.print(p, 4);
  } else if (p <= 0) {
    Serial.print("~0");
  } else {
    int e = (int)floor(log10(p));
    Serial.print(p / pow(10, e), 2);
    Serial.print('e');
    Serial.print(e);
  }
}

static void printPercent(double num, double den) {
  Serial.print(100.0 * num / den, 3);
  Serial.print('%');
}

static void progress(uint32_t done, uint32_t total, uint32_t busyUs, uint32_t &lastMs,
                     const char *unit) {
  if (millis() - lastMs < 2000) return;
  lastMs = millis();
  Serial.print("  ... ");
  Serial.print(100UL * done / total);
  Serial.print("%  (");
  Serial.print(done * 1e6 / busyUs, 1);
  Serial.print(' ');
  Serial.print(unit);
  Serial.println("/s)");
}

static void printVerdict(const char *what) {
  Serial.print("  => ");
  Serial.print(what);
  Serial.print(": ");
  Serial.print(GRADE_NAME[s_worst]);
  Serial.println(" (worst result above)");
  Serial.println();
}

// Prints the bit and byte tests for st; returns the byte min-entropy.
static double reportStats(const ByteStats &st) {
  const double n = st.n, nbits = 8.0 * st.n;
  const uint32_t ones = st.ones();
  double p;

  // Monobit (NIST SP 800-22, 2.1)
  p = erfc(fabs(2.0 * ones - nbits) / sqrt(nbits) / M_SQRT2);
  beginRow(gradeP(p), "Monobit (0/1 balance)");
  Serial.print("ones=");
  printPercent(ones, nbits);
  Serial.print("  ");
  printP(p);
  Serial.println();

  // Bias of a single bit position, Bonferroni-corrected over all 8
  double maxZ = 0;
  int worst = 0;
  for (int i = 0; i < 8; ++i) {
    double z = fabs(2.0 * st.posOnes[i] - n) / sqrt(n);
    if (z > maxZ) { maxZ = z; worst = i; }
  }
  p = fmin(1.0, 8 * erfc(maxZ / M_SQRT2));
  beginRow(gradeP(p), "Bit-position bias");
  Serial.print("worst bit ");
  Serial.print(worst);
  Serial.print(" ones=");
  printPercent(st.posOnes[worst], n);
  Serial.print("  ");
  printP(p);
  Serial.println();

  // Runs (NIST SP 800-22, 2.3): too many / too few 0<->1 flips
  double pi = ones / nbits;
  if (fabs(pi - 0.5) >= 2 / sqrt(nbits)) {
    p = 0;   // prerequisite failed: the stream is already too biased
  } else {
    double v = st.flips + 1.0;
    p = erfc(fabs(v - 2 * nbits * pi * (1 - pi)) / (2 * sqrt(2 * nbits) * pi * (1 - pi)));
  }
  beginRow(gradeP(p), "Runs (bit-to-bit flips)");
  Serial.print("flips=");
  printPercent(st.flips, nbits - 1);
  Serial.print("  ");
  printP(p);
  Serial.println();

  // Longest run of equal bits; about nbits * 2^-L runs of >= L are expected
  p = -expm1(-nbits * pow(2.0, -(double)st.longestRun));
  beginRow(gradeP(p), "Longest run");
  Serial.print(st.longestRun);
  Serial.print(" bits (expect ~");
  Serial.print(log2(nbits), 1);
  Serial.print(")  ");
  printP(p);
  Serial.println();

  // Byte frequencies, chi-square with 255 dof (Wilson-Hilferty to normal)
  double e = n / 256, chi = 0;
  for (int i = 0; i < 256; ++i) chi += (st.hist[i] - e) * (st.hist[i] - e) / e;
  const double k = 255;
  double z = (cbrt(chi / k) - (1 - 2 / (9 * k))) / sqrt(2 / (9 * k));
  p = 0.5 * erfc(z / M_SQRT2);
  beginRow(gradeP(p), "Byte distribution (chi2)");
  Serial.print("chi2=");
  Serial.print(chi, 1);
  Serial.print(" (expect ~255)  ");
  printP(p);
  Serial.println();

  // Lag-1 serial correlation of bytes (as in `ent`, circular)
  double sum = st.sum, sumSq = st.sumSq;
  double sumLag = st.sumLag + (double)st.last * st.first;
  double den = n * sumSq - sum * sum;
  double scc = den == 0 ? 1 : (n * sumLag - sum * sum) / den;
  p = erfc(fabs(scc) * sqrt(n) / M_SQRT2);
  beginRow(gradeP(p), "Serial correlation");
  Serial.print("r=");
  Serial.print(scc, 5);
  Serial.print(" (expect ~0)  ");
  printP(p);
  Serial.println();

  // Shannon entropy per byte, Miller-Madow small-sample correction
  double h = 0;
  int used = 0;
  uint32_t maxCount = 0;
  for (int i = 0; i < 256; ++i) {
    uint32_t c = st.hist[i];
    if (c > maxCount) maxCount = c;
    if (!c) continue;
    double q = c / n;
    h -= q * log2(q);
    ++used;
  }
  h = fmin(8.0, h + (used - 1) / (2 * n * M_LN2));
  // An ideal source stays within ~64/N of 8 bits (spread shrinks with N)
  double deficit = 8 - h;
  beginRow(deficit <= 64 / n ? GREAT : deficit <= 0.05 ? GOOD : deficit <= 0.5 ? OK : BAD,
           "Shannon entropy");
  Serial.print(h, 4);
  Serial.println(" bits/byte (max 8)");

  // Min-entropy (most common byte). Pessimistic at small N, so it is
  // graded against what an ideal source scores at the same N (the most
  // common of 256 bins sits ~2.8 sigma above the mean).
  double hMin = mcvMinEntropy(maxCount, n);
  double ideal = mcvMinEntropy(n / 256 + 2.8 * sqrt(n / 256 * (255.0 / 256)), n);
  double r = hMin / ideal;
  beginRow(r >= 0.97 ? GREAT : r >= 0.9 ? GOOD : r >= 0.75 ? OK : BAD, "Min-entropy (MCV)");
  Serial.print(hMin, 3);
  Serial.print(" bits/byte (ideal source at this N: ~");
  Serial.print(ideal, 3);
  Serial.println(")");

  return hMin;
}

/* ------------------------------------------------------------------ */
/* Test runs                                                           */
/* ------------------------------------------------------------------ */

static void runRngpin() {
  ByteStats &st = s_stats;
  st.reset();
  s_worst = GREAT;
  Serial.print("== RNGpin() output, ");
  Serial.print(s_sampleBytes);
  Serial.println(" bytes (as fed to sha256 in generateWallet) ==");

  uint8_t buf[16];
  uint32_t busyUs = 0, lastMs = millis();
  while (st.n < s_sampleBytes) {
    unsigned len = min((uint32_t)sizeof(buf), s_sampleBytes - st.n);
    uint32_t t0 = micros();
    RNGpin(buf, len);
    busyUs += micros() - t0;
    for (unsigned i = 0; i < len; ++i) st.add(buf[i]);
    progress(st.n, s_sampleBytes, busyUs, lastMs, "bytes");
  }

  reportStats(st);

  double bps = st.n * 1e6 / busyUs;
  beginRow(bps >= 1000 ? GREAT : bps >= 100 ? GOOD : bps >= 10 ? OK : BAD, "Speed");
  Serial.print(bps, 1);
  Serial.print(" bytes/s (32-byte seed: ");
  Serial.print(32000.0 / bps, 0);
  Serial.println(" ms)");
  printVerdict("RNGpin() output");
}

static void runRaw() {
  ByteStats &st = s_stats;
  st.reset();
  s_worst = GREAT;
  Serial.print("== Raw pool bits before whitening, ");
  Serial.print(s_sampleBytes);
  Serial.print(" pools = ");
  Serial.print(s_sampleBytes * 32);
  Serial.println(" samples ==");

  static const char *const SRC_NAME[4] = {
    "A0 LSB (init)", "A1 LSB (red)", "Wait count LSB (count)", "SysTick LSB (jitter)"};
  uint32_t srcOnes[4] = {0, 0, 0, 0};
  uint32_t samples = 0, immediate = 0, guardHits = 0;
  uint64_t waitSum = 0;
  uint32_t busyUs = 0, lastMs = millis();

  for (uint32_t pools = 0; pools < s_sampleBytes; ++pools) {
    uint32_t pool = 0;
    uint32_t t0 = micros();
    for (unsigned i = 0; i < 32; ++i) {
      RawSample s = rawSample();
      pool = (pool << 1) | s.bit;
      srcOnes[0] += s.init;
      srcOnes[1] += s.red;
      srcOnes[2] += s.count;
      srcOnes[3] += s.jitter;
      waitSum += s.waits;
      if (s.waits == 0) ++immediate;
      if (s.waits > 4096) ++guardHits;
    }
    busyUs += micros() - t0;
    samples += 32;
    for (int sh = 24; sh >= 0; sh -= 8) st.add((uint8_t)(pool >> sh));
    progress(pools + 1, s_sampleBytes, busyUs, lastMs, "pools");
  }

  double hByte = reportStats(st);

  // Each source on its own (XORed together, so one biased source is fine)
  for (int i = 0; i < 4; ++i) {
    beginInfo(SRC_NAME[i]);
    Serial.print("ones=");
    printPercent(srcOnes[i], samples);
    Serial.print("  min-entropy ");
    Serial.print(mcvMinEntropy(max(srcOnes[i], samples - srcOnes[i]), samples), 3);
    Serial.println(" bits/sample");
  }
  beginInfo("A0 wait loop");
  Serial.print("avg ");
  Serial.print((double)waitSum / samples, 1);
  Serial.print(" polls, changed at once ");
  printPercent(immediate, samples);
  Serial.print(", hit 4096 guard ");
  printPercent(guardHits, samples);
  Serial.println();
  beginInfo("Speed");
  Serial.print(samples * 1e6 / busyUs, 1);
  Serial.println(" samples/s");

  // XOR whitening cannot add entropy: an output byte holds at most what
  // its 32 raw samples carry. Statistical estimates are upper bounds, a
  // predictable (e.g. timing-deterministic) bit can still look random.
  uint32_t ones = st.ones();
  double hBit = mcvMinEntropy(max(ones, samples - ones), samples);
  double hSample = fmin(hBit, hByte / 8);
  double perByte = 32 * hSample;
  beginRow(perByte >= 16 ? GREAT : perByte >= 8 ? GOOD : perByte >= 4 ? OK : BAD,
           "Entropy per RNGpin() byte");
  Serial.print(hSample, 4);
  Serial.print(" bits/sample x 32 = ");
  Serial.print(fmin(8.0, perByte), 2);
  Serial.print(" of 8 bits (margin x");
  Serial.print(perByte / 8, 2);
  Serial.println(")");
  printVerdict("Raw source");
}

static void streamBinary(bool raw) {
  uint8_t buf[16];
  while (!Serial.available()) {
    if (raw) {
      for (unsigned i = 0; i < sizeof(buf); i += 4) {
        uint32_t pool = rawPool();
        buf[i] = pool >> 24;
        buf[i + 1] = pool >> 16;
        buf[i + 2] = pool >> 8;
        buf[i + 3] = pool;
      }
    } else {
      RNGpin(buf, sizeof(buf));
    }
    Serial.write(buf, sizeof(buf));
  }
  while (Serial.available()) Serial.read();
}

static void printHelp() {
  Serial.println("Soteria RNG test firmware - measures RNGpin() without hashing");
  Serial.println("  a  run both tests          r  RNGpin() output   w  raw pool bits");
  Serial.println("  1/2/3/4  sample size 2 / 4 / 16 / 64 KiB (per test)");
  Serial.println("  b / B  binary stream of RNGpin() / raw pool bytes, any key stops");
  Serial.print("Sample size: ");
  Serial.print(s_sampleBytes);
  Serial.println(" bytes");
  Serial.println("Grades: hypothesis tests (with p) give GOOD / OK (p<0.01, rerun) / BAD");
  Serial.println("(p<1e-4); a perfect source still shows an occasional OK.");
  Serial.println();
}

static void setSize(uint32_t bytes) {
  s_sampleBytes = bytes;
  Serial.print("Sample size: ");
  Serial.print(s_sampleBytes);
  Serial.println(" bytes");
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {}
  printHelp();
}

void loop() {
  if (!Serial.available()) return;
  switch (Serial.read()) {
    case 'a': runRngpin(); runRaw(); break;
    case 'r': runRngpin(); break;
    case 'w': runRaw(); break;
    case '1': setSize(2048); break;
    case '2': setSize(4096); break;
    case '3': setSize(16384); break;
    case '4': setSize(65536); break;
    case 'b': streamBinary(false); break;
    case 'B': streamBinary(true); break;
    case '\r': case '\n': break;
    default: printHelp();
  }
}
