# Example SignedURL Generator Service

This is a sample Service that generates signedURLs suitable for use with GCS.  It
could be deployed as a service into Google Cloud Run.
Built on Java11, and [javalin](https://javalin.io).


## Disclaimer

This tool is not an official Google product, nor is it part of an official Google product.

# Usage Examples

## Get a signed URL - Sending a Private Key

```
curl ${endpoint}/sign -H content-type:application/json -d '{
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

Example output:
```
{
  "string-to-sign": "GOOG4-RSA-SHA256\n20240502T202357Z\n20240502/us/storage/goog4_request\ne02237c99373a9a7ae3913e83667e5a1e0a47e0e6de1ff0dcbad4a936231c293",
  "now": "2024-05-02T20:23:57.997057Z",
  "signed-url": "https://storage.googleapis.com/unique-bucket-id/cute-kittens.png?X-Goog-Algorithm\u003dGOOG4-RSA-SHA256\u0026X-Goog-Credential\u003dstorage-reader-4109%40infinite-epoch-2900.iam.gserviceaccount.com%2F20240502%2Fus%2Fstorage%2Fgoog4_request\u0026X-Goog-Date\u003d20240502T202357Z\u0026X-Goog-Expires\u003d60\u0026X-Goog-SignedHeaders\u003dhost\u0026X-Goog-Signature\u003d0d2593bc82a49cb2ddfebbdc76dfac6b6ca1752300eb1944b31ef7596922f98cb09a1cd9e81056183367b4baebc98452790dba803c6afa7636145820cb20a78bc9ba335cf82906738835562cc41e68016b4ef1c139b441c92425ae5efa482166c4e749d896905ca82a13a14437cdf1482b934dc92008e206692614b071add60d740ee47242249d6e101d3effc29cca3963825b4c3463e5f4fcbe8f5f13872fc1a06ece86d556d1c927741d274ea9ff692ee85960c4ea41145fed860ac98cc43652c8a42cefc855c38fa1682e26e116b3449e565d06a7bc8be887975a7965dcdb38175abebe15d19d352f8c891a8013b6a35556c2d6fab780df3ca7e514f9d501",
  "expiration": "2024-05-02T20:24:57Z"
}
```

Please note: the "signed-url" property is JS-encoded.  Instead of a query param
like `X-Goog-Algorithm=GOOG4-RSA-SHA256`, you see
`X-Goog-Algorithm\u003dGOOG4-RSA-SHA256` in the above.  Your app will need to
decode that URL, before trying to dereference it.  You cannot simply copy/paste
that into the browser address bar.



## Get a signed URL - via signBlob

There's a second
option, to use the [signBlob
method](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signBlob).
This does not require that the caller send in a private key.  Instead the caller sends in the full email  of the service account, that should generate the signed url.

The request looks like this:

```
curl ${endpoint}/sign2 -H content-type:application/json -d '{
  "verb": "GET",
  "expires-in": "60s",
  "bucket": "unique-bucket-id",
  "object": "cute-kittens.png",
  "service-account-email": "storage-reader-123456@my-gcp-project-id.iam.gserviceaccount.com"
}
'
```

BUT!  To make this work, you need to perform some additional setup, which is described below.


## Inquire (diagnostics)

```
curl -i 0:8080/info
```

Example output:
```
{
  "build-time": "2024-05-02T20:57:12Z",
  "project-version": "20240502"
}
```


## Building and Deploying

Use Java 11 or later. You should have [Apache maven](https://maven.apache.org/download.cgi), at least v3.6.3

Build:
```
mvn clean package
```

Run locally:
```
java -cp "target/lib/*" -jar target/signed-url-generator-20240502.jar
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

1. Build the container image locally, and publish it to Artifact Registry:
   ```
   export PROJECT_ID=your-gcp-project-here
   mvn package jib:build
   ```

   Observe the output URL for the image.  It will look like:
   ```
   gcr.io/YOUR-GCP-PROJECT-HERE/cloud-builds-submit/signed-url-generator-container:20240502
   ```

   Optionally, you could now run the image locally, or in any container platform.

2. Deploy that image to Cloud Run:
   ```
   gcloud run deploy signedurl-service \
     --image gcr.io/${PROJECT_ID}/cloud-builds-submit/signed-url-generator-container:20240502 \
     --cpu 1 \
     --memory '256Mi' \
     --min-instances 0 \
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
PROJECT_ID=your-gcp-project-here
gcloud run deploy signedurl-service \
 --source . \
 --cpu 1 \
 --memory '256Mi' \
 --min-instances 0 \
 --max-instances 1 \
 --allow-unauthenticated \
 --project ${PROJECT_ID}\
 --region us-west1 \
 --timeout 300
```

And again, access it via the URL emitted by that command.


## Additional Setup for Using signBlob

[`signBlob`](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signBlob) is a method on the `iamcredentials` API in Google Cloud.
It signs a blob using the system-managed private key for a particular service account. Using the signBlob approach means you do not need to transmit a private key to the service, in order to generated the signed URL.

To make this signing service work with signBlob, you must:

1. Grant role `iam.serviceAccountTokenCreator` on the Service Account that will generate the signature, to the Service Account that the Cloud Run service runs as.
   Do this with:

   ```
   EMAIL_OF_SA_FOR_SIGNING=storage-reader-123456@my-gcp-project-id.iam.gserviceaccount.com
   EMAIL_OF_SA_FOR_SERVICE=signing-service-abc123@my-gcp-project-id.iam.gserviceaccount.com
   gcloud iam service-accounts add-iam-policy-binding ${EMAIL_OF_SA_FOR_SIGNING} \
     --member="serviceAccount:${EMAIL_OF_SA_FOR_SERVICE}" \
     --role='roles/iam.serviceAccountTokenCreator' \
     --project "$PROJECT_ID"

   ```

   This is required even if you use the same Service account for the Cloud Run service, as you do for signing.


2. Deploy the service into Cloud run with that Service account:
   ```
   gcloud run deploy signedurl-service \
     --image gcr.io/${PROJECT_ID}/cloud-builds-submit/signed-url-generator-container:20240502 \
     --cpu 1 \
     --memory '256Mi' \
     --min-instances 0 \
     --max-instances 1 \
     --allow-unauthenticated \
     --project ${PROJECT_ID} \
     --service-account ${EMAIL_OF_SA_FOR_SERVICE}" \
     --region us-west1 \
     --timeout 300
   ```

3. Restrict who can access this service! Remember, anyone with access to the URL can generate signed URLs.


4. Then you can invoke the service:
   ```
   curl ${endpoint}/sign2 -H content-type:application/json -d '{
     "verb": "GET",
     "expires-in": "60s",
     "bucket": "unique-bucket-id",
     "object": "cute-kittens.png",
     "service-account-email": "'${EMAIL_OF_SA_FOR_SIGNING}'"
   }
   '
   ```


## License

This material is Copyright 2019-2024 Google LLC and is licensed under the
[Apache 2.0 License](LICENSE).


## Bugs

- ??
