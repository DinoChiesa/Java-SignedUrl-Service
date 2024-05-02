// Copyright © 2024 Google, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// All rights reserved.

//
// This service generates signed urls for Google Cloud Storage. It exposes
// these endpoints
//
//   POST /sign
//     for generating signed URL with the given input
//
//     payload:
//     {
//       "verb": "GET",
//       "expires-in": "60s",
//       "bucket": "dchiesa-sample-bucket",
//       "object": "clarify-argolis.png",
//       "service-account-key": {
//         "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
//         "client_email": "storage-reader-4109@infinite-epoch-2900.iam.gserviceaccount.com"
//       }
//     }
//
//   GET /info
//     for returning info about the service
//
//

package com.google.examples;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.javalin.Javalin;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

public class SignedUrlGeneratorService {
  private static final Logger logger;

  static {
    try (InputStream stream = getLoggingConfig()) {
      LogManager.getLogManager().readConfiguration(stream);
    } catch (Exception e1) {
      System.out.printf("Exception while initializing log: %s\n", e1.toString());
    }

    logger = Logger.getLogger("SignedUrlGeneratorService");
  }

  private static InputStream getLoggingConfig() throws FileNotFoundException {
    final String propertyName = "java.util.logging.config.file";
    String presetFile = System.getProperty(propertyName);
    if (presetFile == null) {
      return getResourceAsStream("logging.properties");
    }
    return new FileInputStream(presetFile);
  }

  public static InputStream getResourceAsStream(String resourceName) {
    // forcibly prepend a slash. not sure if necessary.
    if (!resourceName.startsWith("/")) {
      resourceName = "/" + resourceName;
    }
    if (!resourceName.startsWith("/resources")) {
      resourceName = "/resources" + resourceName;
    }
    InputStream in = SignedUrlGeneratorService.class.getResourceAsStream(resourceName);
    return in;
  }

  private static String manifestAttribute(final Manifest manifest, final String needle) {
    if (manifest != null) {
      Attributes attr = manifest.getMainAttributes();
      String value =
          attr.keySet().stream()
              .filter(key -> needle.equals(key.toString()))
              .findFirst()
              .map(key -> attr.getValue((Attributes.Name) key))
              .orElse("-not set-");
      return value;
    }
    return "unknown";
  }

  private static Manifest getManifest() throws Exception {
    Class clazz = SignedUrlGeneratorService.class;
    String className = clazz.getSimpleName() + ".class";
    String classPath = clazz.getResource(className).toString();
    if (!classPath.startsWith("jar")) {
      return null;
    }
    String manifestPath =
        classPath.replace(
            "com/google/examples/SignedUrlGeneratorService.class", "META-INF/MANIFEST.MF");
    try (InputStream input = new URL(manifestPath).openStream()) {
      Manifest manifest = new Manifest(input);
      return manifest;
    } catch (IOException e1) {
      logger.log(Level.WARNING, "Exception reading Manifest", e1);
      e1.printStackTrace();
      return null;
    }
  }

  public SignedUrlGeneratorService() {}

  public static void main(String[] args) {
    try {
      Manifest manifest = getManifest();
      String buildTime = manifestAttribute(manifest, "Build-Time");
      String projectVersion = manifestAttribute(manifest, "Project-Version");
      logger.info(
          String.format("SignedUrlGeneratorService v%s build time %s", projectVersion, buildTime));
      int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
      SignedUrlGenerator signedUrlGenerator = new SignedUrlGenerator();

      var app =
          Javalin.create(
                  config -> {
                    config.requestLogger.http(
                        (ctx, ms) -> {
                          // this gets called after the request has been handled.
                          logger.info(
                              String.format(
                                  "%s %s => %d", ctx.method(), ctx.path(), ctx.status().getCode()));
                        });
                  })
              .error(404, ctx -> ctx.result("Not Found"))
              .get(
                  "/info",
                  (ctx) -> {
                    Gson gson = new GsonBuilder().setPrettyPrinting().create();
                    Map<String, String> result = new HashMap<String, String>();
                    result.put("build-time", buildTime);
                    result.put("project-version", projectVersion);
                    // maybe add some java properties here?

                    ctx.contentType("application/json; charset=utf-8")
                        .status(200)
                        .result(gson.toJson(result) + "\n");
                    // logger.info(String.format("%s %s => 200", ctx.method(), ctx.path()));
                  })
              .post("/sign", signedUrlGenerator::generateSignature)
              .start(port);

    } catch (java.lang.Exception exc1) {
      logger.log(Level.SEVERE, "Exception in main()", exc1);
      exc1.printStackTrace();
    }
  }
}
