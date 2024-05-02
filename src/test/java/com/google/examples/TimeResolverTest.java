package com.google.examples;

import java.util.ArrayList;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TimeResolverTest {
  @DataProvider(name = "batch1")
  public static Object[][] getTestcases1() {
    ArrayList<Object[]> list = new ArrayList<Object[]>();
    list.add(new Object[] {"42", 42L});
    list.add(new Object[] {"10s", 10L});
    list.add(new Object[] {"1m", 60L});
    list.add(new Object[] {"10m", 600L});
    list.add(new Object[] {"3h", 10800L});
    list.add(new Object[] {"4d", 4 * 86400L});

    return list.stream().toArray(Object[][]::new);
  }

  @Test(dataProvider = "batch1")
  public void testResolveExpression(String input, Long expectedValue) {
    Assert.assertEquals(TimeResolver.resolveExpression(input), expectedValue);
  }
}
