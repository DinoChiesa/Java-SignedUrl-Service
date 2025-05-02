// Copyright © 2020-2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

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
