package se.sics.prototype.groupapps;

import java.time.*;
import java.time.temporal.ChronoUnit;

public class IndoorSimulator {

    private static final ZoneId ZONE = ZoneId.of("Europe/Stockholm");

    // ---------- Public API ----------

    public static double simulateTemperatureCelsius(LocalDateTime time, String roomName) {
        RoomProfile p = RoomProfile.of(roomName);
        Weather w = weatherAt(time);

        double hour = fractionalHour(time);
        double occ = occupancyLevel(time, p);

        // Indoor setpoint changes slightly by room and season.
        // Heating keeps winter indoor temp fairly stable; summer drifts a bit warmer.
        double seasonalSetpoint =
                21.2
                + 0.6 * summerFactor(time)
                - 0.2 * winterFactor(time)
                + p.tempBias;

        // Solar/daylight effect: warmest in afternoon, stronger in summer.
        double daylightGain =
                p.solarGain * daylightFactor(time) * (0.6 + 0.8 * summerFactor(time));

        // Occupancy/equipment load.
        double internalGain =
                occ * p.occupancyHeatGain
                + officeHoursShape(hour) * p.equipmentGain;

        // Outdoor coupling: still indoor, so heavily damped.
        double outdoorInfluence = p.outdoorTempCoupling * (w.outdoorTempC - 8.0);

        // Smooth room-specific micro variation
        double micro =
                0.35 * smoothNoise(roomName + ":temp:6h", epochHours(time) / 6.0) +
                0.20 * smoothNoise(roomName + ":temp:1h", epochHours(time));

        double temp =
                seasonalSetpoint
                + daylightGain
                + internalGain
                + outdoorInfluence
                + micro;

        return round1(softClamp(temp, 17.0, 28.0));
    }

    public static int simulateCO2ppm(LocalDateTime time, String roomName) {
        RoomProfile p = RoomProfile.of(roomName);

        double occ = occupancyLevel(time, p);

        // Background near outdoor when room is unused.
        double baseline =
                430
                + 18 * smoothNoise(roomName + ":co2:1d", epochDays(time))
                + p.co2Bias;

        // Busy meeting rooms climb strongly with occupancy.
        // Add meeting burstiness without discontinuity.
        double burst =
                p.meetingBurstiness * positive(
                        smoothNoise(roomName + ":meeting:30m", epochMinutes(time) / 30.0));

        double effectiveOcc = clamp01(occ + 0.35 * burst);

        double ventilationEffect =
                1.0 - p.ventilationQuality; // worse ventilation => larger rise

        double rise =
                effectiveOcc * (350 + 900 * ventilationEffect + 250 * p.capacityFactor);

        // Slow decay-ish variation when nearly empty
        double residual =
                (1.0 - effectiveOcc) * 40 *
                smoothNoise(roomName + ":co2Residual:2h", epochHours(time) / 2.0);

        double co2 = baseline + rise + residual;

        return (int) Math.round(softClamp(co2, 400, 1800));
    }

    public static double simulateHumidity(LocalDateTime time, String roomName) {
        RoomProfile p = RoomProfile.of(roomName);
        Weather w = weatherAt(time);

        double occ = occupancyLevel(time, p);

        // Indoors tends to be driest in winter, less dry in summer/autumn.
        // Outdoor RH influences it, but damped strongly indoors.
        double seasonalBase =
                36.0
                - 6.0 * winterFactor(time)
                + 4.0 * summerFactor(time)
                + p.humidityBias;

        double outdoorCoupling = p.outdoorHumidityCoupling * (w.outdoorHumidityPct - 75.0);

        // Occupancy nudges RH slightly upward.
        double peopleMoisture = occ * (2.0 + 2.5 * p.capacityFactor);

        // Heating/afternoon dryness
        double dailyDrying =
                -2.5 * officeHoursShape(fractionalHour(time)) * (0.5 + winterFactor(time));

        double noise =
                1.4 * smoothNoise(roomName + ":rh:4h", epochHours(time) / 4.0) +
                0.6 * smoothNoise(roomName + ":rh:1h", epochHours(time));

        double rh = seasonalBase + outdoorCoupling + peopleMoisture + dailyDrying + noise;

        return round1(softClamp(rh, 22.0, 62.0));
    }

    public static double simulatePressure(LocalDateTime time, String roomName) {
        RoomProfile p = RoomProfile.of(roomName);
        Weather w = weatherAt(time);

        // Indoor pressure should mostly mirror outdoor weather.
        // Only tiny room/sensor bias should differ.
        double pressure = w.pressureHpa + p.pressureBias
                + 0.15 * smoothNoise(roomName + ":pressure:12h", epochHours(time) / 12.0);

        return round1(softClamp(pressure, 985.0, 1045.0));
    }

    // Convenience wrappers using Stockholm timezone
    public static double simulateTemperatureCelsius(String roomName) {
        return simulateTemperatureCelsius(LocalDateTime.now(ZONE), roomName);
    }

    public static int simulateCO2ppm(String roomName) {
        return simulateCO2ppm(LocalDateTime.now(ZONE), roomName);
    }

    public static double simulateHumidity(String roomName) {
        return simulateHumidity(LocalDateTime.now(ZONE), roomName);
    }

    public static double simulatePressure(String roomName) {
        return simulatePressure(LocalDateTime.now(ZONE), roomName);
    }

    // ---------- Shared weather driver ----------

    private static Weather weatherAt(LocalDateTime time) {
        double dayOfYear = fractionalDayOfYear(time);
        double hour = fractionalHour(time);

        // Stockholm-like yearly outdoor temp pattern:
        // coldest around late Jan / early Feb, warmest around mid/late July.
        double annualTemp =
                7.0 + 9.5 * Math.sin(2.0 * Math.PI * (dayOfYear - 109.0) / 365.2425);

        // Daily temperature cycle stronger in summer, weaker in winter.
        double dailyAmp = 1.0 + 2.5 * summerFactor(time);
        double diurnal =
                dailyAmp * Math.sin(2.0 * Math.PI * (hour - 15.0) / 24.0);

        // Synoptic weather systems (multi-day smooth variation)
        double weatherSwing =
                3.2 * smoothNoise("stockholm:temp:5d", epochHours(time) / 24.0 / 5.0) +
                1.3 * smoothNoise("stockholm:temp:1d", epochDays(time));

        double outdoorTempC = annualTemp + diurnal + weatherSwing;

        // Pressure: synoptic scale, shared by all rooms.
        double pressureHpa =
                1013.0
                + 11.0 * smoothNoise("stockholm:pressure:7d", epochDays(time) / 7.0)
                + 4.0 * smoothNoise("stockholm:pressure:2d", epochDays(time) / 2.0);

        // Outdoor RH inversely related to temp a bit, but still smooth.
        double outdoorHumidityPct =
                78.0
                - 8.0 * summerFactor(time)
                + 6.0 * winterFactor(time)
                - 0.35 * (outdoorTempC - 7.0)
                + 8.0 * smoothNoise("stockholm:rh:3d", epochDays(time) / 3.0);

        outdoorHumidityPct = softClamp(outdoorHumidityPct, 45.0, 98.0);

        return new Weather(outdoorTempC, outdoorHumidityPct, pressureHpa);
    }

    // ---------- Occupancy ----------

    private static double occupancyLevel(LocalDateTime time, RoomProfile p) {
        DayOfWeek d = time.getDayOfWeek();
        double hour = fractionalHour(time);

        boolean weekday = d.getValue() >= 1 && d.getValue() <= 5;

        // Base schedule:
        // weekdays active, weekends mostly unused.
        double base;
        if (!weekday) {
            base = 0.03 + 0.06 * positive(
                    smoothNoise(p.name + ":weekendUse:2h", epochHours(time) / 2.0));
        } else {
            // Smooth office-day shape: rise in morning, dip at lunch, fall after 17-18.
            double morningRamp = logistic((hour - 8.0) * 1.6);
            double eveningDrop = 1.0 - logistic((hour - 17.5) * 1.5);
            double lunchDip = 0.22 * gaussian(hour, 12.2, 1.0);

            base = p.baseWeekdayOccupancy * morningRamp * eveningDrop * (1.0 - lunchDip);

            // Reduced use Friday afternoon
            if (d == DayOfWeek.FRIDAY) {
                base *= 1.0 - 0.18 * logistic((hour - 14.0) * 1.1);
            }

            // Add meeting pulses: room-specific and smooth
            double pulses =
                    0.18 * positive(smoothNoise(p.name + ":pulse:90m", epochMinutes(time) / 90.0))
                    + 0.10 * positive(smoothNoise(p.name + ":pulse:30m", epochMinutes(time) / 30.0));

            base += pulses * p.meetingActivity;
        }

        return clamp01(base);
    }

    // ---------- Time helpers ----------

    private static double fractionalHour(LocalDateTime t) {
        return t.getHour() + t.getMinute() / 60.0 + t.getSecond() / 3600.0 + t.getNano() / 3_600_000_000_000.0;
    }

    private static double fractionalDayOfYear(LocalDateTime t) {
        return t.getDayOfYear() + fractionalHour(t) / 24.0;
    }

    private static double epochMinutes(LocalDateTime t) {
        return t.atZone(ZONE).toEpochSecond() / 60.0;
    }

    private static double epochHours(LocalDateTime t) {
        return t.atZone(ZONE).toEpochSecond() / 3600.0;
    }

    private static double epochDays(LocalDateTime t) {
        return t.atZone(ZONE).toEpochSecond() / 86400.0;
    }

    // ---------- Seasonal/daylight helpers ----------

    private static double summerFactor(LocalDateTime time) {
        double d = fractionalDayOfYear(time);
        return 0.5 + 0.5 * Math.sin(2.0 * Math.PI * (d - 109.0) / 365.2425);
    }

    private static double winterFactor(LocalDateTime time) {
        return 1.0 - summerFactor(time);
    }

    private static double daylightFactor(LocalDateTime time) {
        double h = fractionalHour(time);

        // Smooth daytime proxy, later peak in afternoon.
        double rise = logistic((h - 7.5) * 1.1);
        double fall = 1.0 - logistic((h - 18.0) * 1.1);

        // Summer has much more daylight influence than winter in Stockholm.
        return clamp01(rise * fall) * (0.35 + 0.95 * summerFactor(time));
    }

    private static double officeHoursShape(double hour) {
        double on = logistic((hour - 8.0) * 1.3);
        double off = 1.0 - logistic((hour - 18.0) * 1.2);
        return clamp01(on * off);
    }

    // ---------- Smooth deterministic noise ----------

    /**
     * Continuous value noise in [-1, 1].
     * Example:
     *   smoothNoise("roomA:temp", epochHours / 6.0)
     * gives one smoothly interpolated random anchor every 6 hours.
     */
    private static double smoothNoise(String key, double x) {
        long x0 = (long) Math.floor(x);
        long x1 = x0 + 1;
        double t = x - x0;
        double v0 = hashToUnit(key, x0);
        double v1 = hashToUnit(key, x1);
        double s = t * t * (3.0 - 2.0 * t); // smoothstep
        return lerp(v0, v1, s);
    }

    private static double hashToUnit(String key, long x) {
        long h = 1469598103934665603L;
        for (int i = 0; i < key.length(); i++) {
            h ^= key.charAt(i);
            h *= 1099511628211L;
        }
        h ^= x + 0x9E3779B97F4A7C15L;
        h *= 0xBF58476D1CE4E5B9L;
        h ^= (h >>> 30);
        h *= 0x94D049BB133111EBL;
        h ^= (h >>> 31);

        // map to [-1,1]
        double u = ((h >>> 11) & ((1L << 53) - 1)) / (double)(1L << 53);
        return 2.0 * u - 1.0;
    }

    // ---------- Profiles ----------

    private static final class RoomProfile {
        final String name;
        final double tempBias;
        final double humidityBias;
        final double pressureBias;
        final double co2Bias;

        final double outdoorTempCoupling;
        final double outdoorHumidityCoupling;
        final double ventilationQuality;   // 0..1 high is good
        final double baseWeekdayOccupancy; // 0..1
        final double meetingActivity;      // 0..1
        final double capacityFactor;       // 0..1
        final double solarGain;
        final double equipmentGain;
        final double occupancyHeatGain;
        final double meetingBurstiness;

        private RoomProfile(
                String name,
                double tempBias,
                double humidityBias,
                double pressureBias,
                double co2Bias,
                double outdoorTempCoupling,
                double outdoorHumidityCoupling,
                double ventilationQuality,
                double baseWeekdayOccupancy,
                double meetingActivity,
                double capacityFactor,
                double solarGain,
                double equipmentGain,
                double occupancyHeatGain,
                double meetingBurstiness) {
            this.name = name;
            this.tempBias = tempBias;
            this.humidityBias = humidityBias;
            this.pressureBias = pressureBias;
            this.co2Bias = co2Bias;
            this.outdoorTempCoupling = outdoorTempCoupling;
            this.outdoorHumidityCoupling = outdoorHumidityCoupling;
            this.ventilationQuality = ventilationQuality;
            this.baseWeekdayOccupancy = baseWeekdayOccupancy;
            this.meetingActivity = meetingActivity;
            this.capacityFactor = capacityFactor;
            this.solarGain = solarGain;
            this.equipmentGain = equipmentGain;
            this.occupancyHeatGain = occupancyHeatGain;
            this.meetingBurstiness = meetingBurstiness;
        }

        static RoomProfile of(String roomName) {
            // deterministic per-room coefficients
            double a = normalizedHash(roomName + ":a");
            double b = normalizedHash(roomName + ":b");
            double c = normalizedHash(roomName + ":c");
            double d = normalizedHash(roomName + ":d");

            return new RoomProfile(
                    roomName,
                    lerp(-0.8, 0.8, a),
                    lerp(-3.0, 3.0, b),
                    lerp(-0.6, 0.6, c),
                    lerp(-25.0, 25.0, d),

                    lerp(0.05, 0.18, normalizedHash(roomName + ":tempCoupling")),
                    lerp(0.08, 0.22, normalizedHash(roomName + ":rhCoupling")),
                    lerp(0.45, 0.90, normalizedHash(roomName + ":vent")),
                    lerp(0.35, 0.85, normalizedHash(roomName + ":weekdayOcc")),
                    lerp(0.30, 0.95, normalizedHash(roomName + ":meeting")),
                    lerp(0.20, 1.00, normalizedHash(roomName + ":capacity")),
                    lerp(0.10, 0.90, normalizedHash(roomName + ":solar")),
                    lerp(0.05, 0.60, normalizedHash(roomName + ":equip")),
                    lerp(0.20, 1.00, normalizedHash(roomName + ":occHeat")),
                    lerp(0.10, 0.80, normalizedHash(roomName + ":burst"))
            );
        }
    }

    private record Weather(double outdoorTempC, double outdoorHumidityPct, double pressureHpa) {}

    // ---------- Math helpers ----------

    private static double normalizedHash(String s) {
        long h = 1125899906842597L;
        for (int i = 0; i < s.length(); i++) {
            h = 31 * h + s.charAt(i);
        }
        double u = ((h >>> 11) & ((1L << 53) - 1)) / (double)(1L << 53);
        return u;
    }

    private static double softClamp(double x, double min, double max) {
        double mid = 0.5 * (min + max);
        double half = 0.5 * (max - min);
        return mid + half * Math.tanh((x - mid) / half * 1.25);
    }

    private static double logistic(double x) {
        return 1.0 / (1.0 + Math.exp(-x));
    }

    private static double gaussian(double x, double mean, double sigma) {
        double z = (x - mean) / sigma;
        return Math.exp(-0.5 * z * z);
    }

    private static double positive(double x) {
        return Math.max(0.0, x);
    }

    private static double clamp01(double x) {
        return Math.max(0.0, Math.min(1.0, x));
    }

    private static double lerp(double a, double b, double t) {
        return a + (b - a) * t;
    }

    private static double round1(double x) {
        return Math.round(x * 10.0) / 10.0;
    }
}
