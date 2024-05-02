package com.google.examples;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TimeResolver {
  private static final Pattern expiryPattern =
      Pattern.compile("^([1-9][0-9]*)(ms|s|m|h|d|w|)$", Pattern.CASE_INSENSITIVE);
  private static final Map<String, Long> timeMultipliers;

  static {
    Map<String, Long> m1 = new HashMap<String, Long>();
    m1.put("s", 1L);
    m1.put("m", 60L);
    m1.put("h", 60L * 60);
    m1.put("d", 60L * 60 * 24);
    m1.put("w", 60L * 60 * 24 * 7);
    // m1.put("y", 60*60*24*365*1000);
    timeMultipliers = m1;
  }

  private static final String defaultUnit = "s";

  public static Date getExpiryDate(String expiresInString) {
    Calendar cal = Calendar.getInstance();
    Long seconds = resolveExpression(expiresInString);
    int secondsToAdd = seconds.intValue();
    if (secondsToAdd <= 0) {
      return null; /* no expiry */
    }
    cal.add(Calendar.SECOND, secondsToAdd);
    Date then = cal.getTime();
    return then;
  }

  /*
   * convert a simple timespan string, expressed in days, hours, minutes, or
   * seconds, such as 30d, 12d, 8h, 24h, 45m, 30s, into a numeric quantity in
   * seconds. Default TimeUnit is ms. Eg. 30 is treated as 30ms.
   */
  public static Long resolveExpression(String subject) {
    Matcher m = expiryPattern.matcher(subject);
    if (m.find()) {
      String key = m.group(2);
      if (key.equals("")) key = defaultUnit;
      return Long.parseLong(m.group(1), 10) * timeMultipliers.get(key);
    }
    return -1L;
  }
}
