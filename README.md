# Example SignedURL Generator Service

This is a sample Service that generates signedURLs suitable for use with GCS.  It
could be deployed as a service into Google Cloud Run.
Built on Java11, and [javalin](https://javalin.io).


## Disclaimer

This tool is not an official Google product, nor is it part of an official Google product.

# Usage Examples

## Inquire keys

```
curl 0:8080/sign -H content-type:application/json -d '{
  "verb": "GET",
  "expires-in": "60s",
  "bucket": "unique-bucket-id",
  "object": "cute-kittens.png",
  "service-account-key": {
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
    "client_email": "storage-reader-123456@my-gcp-project-id.iam.gserviceaccount.com"
  }
}
'
```

## Inquire

```
curl -i 0:8080/info
```


## Building and Deploying

Use Java 11.

Build:
```
 mvn clean package
```

Run locally:
```
 java -cp "target/lib/*" -jar target/signed-url-generator-20240501.jar
```

Access it at: http://localhost:8080/ .


## Hosting in Google Cloud Run

Via the gcloud console, create a project. Name it whatever you like. Enable
Cloud Run on the project. You may have to enable billing too.

There are lots of ways  to build a container image and then host it on Cloud Run.

There are two options - _alternatives_ - desceribed here:

- build an image locally with the maven tool, and then deploy the built image.
- use `gcloud run deploy` to build from source AND deploy, in one step


### Building locally and deploying separately

1. Modify the pom.xml file to specify YOUR projectId in the properties element.
   ```
  <properties>
    ...
    <gcp-project-name>your-gcp-project-here</gcp-project-name> <!-- HERE -->
  </properties>
  ```

2. Build the container image locally, and publish it to Artifact Registry:
   ```
   PROJECT_ID=my-gcp-project mvn compile jib:build`
   ```

   Observe the output URL for the image.  It will look like:
   ```
   gcr.io/YOUR-PROJECT-ID/cloud-builds-submit/signed-url-generator-container:20240501
   ```

   Optionally, you could now run the image locally, or in any container platform.

3. Deploy that image to Cloud Run:
   ```
   PROJECT_ID=your-gcp-project
   gcloud run deploy signedurl-service \
     --image gcr.io/${PROJECT_ID}/cloud-builds-submit/signed-url-generator-container:20240501 \
     --cpu 1 \
     --memory '256Mi' \
     --min-instances 1 \
     --max-instances 1 \
     --allow-unauthenticated \
     --project ${PROJECT_ID}\
     --region us-west1 \
     --timeout 300
   ```

Access it via the URL emitted by that command.


### Building and Deploying in one step

Use the gcloud command line tool to build and deploy in one step.
```
PROJECT_ID=your-gcp-project
gcloud run deploy signedurl-service \
 --source . \
 --cpu 1 \
 --memory '256Mi' \
 --min-instances 1 \
 --max-instances 1 \
 --allow-unauthenticated \
 --project ${PROJECT_ID}\
 --region us-west1 \
 --timeout 300
```

And again, access it via the URL emitted by that command.


## License

This material is Copyright 2019-2024
Google LLC and is licensed under the [Apache 2.0
License](LICENSE).


## Bugs

- This implementation requires that the caller send in the private key.
  To be correct, the implementation should retrieve the private key from the
  Google Cloud Secret Manager.
