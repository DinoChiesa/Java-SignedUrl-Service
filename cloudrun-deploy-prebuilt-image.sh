#!/bin/bash
# -*- mode: shell-script; sh-shell: bash; coding: utf-8 -*-

SA_REQUIRED_ROLES=("roles/storage.objectCreator" "roles/storage.objectViewer")

env_vars_to_check=(
  "CLOUDRUN_PROJECT"
  "CLOUDRUN_REGION"
  "REPOSITORY_PROJECT"
  "SERVICE_ACCOUNT"
)

source ./lib/utils.sh

check_and_maybe_create_sa() {
  local ROLE AVAILABLE_ROLES project
  project=$1
  echo "gcloud iam service-accounts describe ${FULL_SA_EMAIL} --project=$project"
  if gcloud iam service-accounts describe "${FULL_SA_EMAIL}" --project="$project" --quiet 2>&1; then
    printf "That service account already exists.\n"
    printf "Checking for required roles....\n"
    # shellcheck disable=SC2076
    AVAILABLE_ROLES=($(gcloud projects get-iam-policy "${project}" \
      --flatten="bindings[].members" \
      --filter="bindings.members:${FULL_SA_EMAIL}" |
      grep -v deleted | grep -A 1 members | grep role | sed -e 's/role: //'))

    for j in "${!SA_REQUIRED_ROLES[@]}"; do
      ROLE=${SA_REQUIRED_ROLES[j]}
      printf "    check the role %s...\n" "$ROLE"
      if ! [[ ${AVAILABLE_ROLES[*]} =~ "${ROLE}" ]]; then
        printf "Adding role %s...\n" "${ROLE}"
        echo "gcloud projects add-iam-policy-binding ${project} \
                 --condition=None \
                 --member=serviceAccount:${FULL_SA_EMAIL} \
                 --role=${ROLE}"
        if gcloud projects add-iam-policy-binding "${project}" \
          --condition=None \
          --member="serviceAccount:${FULL_SA_EMAIL}" \
          --role="${ROLE}" --quiet; then
          printf "Success\n"
        else
          printf "\n*** FAILED\n\n"
          printf "You must manually run:\n\n"
          echo "gcloud projects add-iam-policy-binding ${project} \
                 --condition=None \
                 --member=serviceAccount:${FULL_SA_EMAIL} \
                 --role=${ROLE}"
        fi
      else
        printf "      That role is already set.\n"
      fi
    done

  else
    printf "Creating Service account (%s)...\n" "${FULL_SA_EMAIL}"
    echo "gcloud iam service-accounts create $SERVICE_ACCOUNT --project=$project"
    gcloud iam service-accounts create "$SERVICE_ACCOUNT" --project="$project" --quiet 2>&1

    printf "There can be errors if all these changes happen too quickly, so we need to sleep a bit...\n"
    sleep 12

    printf "Granting access for that service account to project %s...\n" "$project"
    for j in "${!SA_REQUIRED_ROLES[@]}"; do
      ROLE=${SA_REQUIRED_ROLES[j]}
      printf "  Adding role %s...\n" "${ROLE}"
      echo "gcloud projects add-iam-policy-binding ${project} \
               --condition=None \
               --member=serviceAccount:${FULL_SA_EMAIL} \
               --role=${ROLE}"
      if gcloud projects add-iam-policy-binding "${project}" \
        --condition=None \
        --member="serviceAccount:${FULL_SA_EMAIL}" \
        --role="${ROLE}" --quiet; then
        printf "Success\n"
      else
        printf "\n*** FAILED\n\n"
        printf "You must manually run:\n\n"
        echo "gcloud projects add-iam-policy-binding ${project} \
                 --condition=None \
                 --member=serviceAccount:${FULL_SA_EMAIL} \
                 --role=${ROLE}"
      fi
    done
  fi
}

check_shell_variables "${env_vars_to_check[@]}"

if [[ "${SERVICE_ACCOUNT}" == *"@"* ]]; then
  printf "The SERVICE_ACCOUNT variable should not contain an @ character.\n"
  exit 1
fi

FULL_SA_EMAIL="${SERVICE_ACCOUNT}@${CLOUDRUN_PROJECT}.iam.gserviceaccount.com"
check_and_maybe_create_sa "${CLOUDRUN_PROJECT}"

IMAGE_VERSION=$(xmllint --xpath "//*[local-name()='project']/*[local-name()='version']/text()" pom.xml)
ARTIFACT_ID=$(xmllint --xpath "//*[local-name()='project']/*[local-name()='artifactId']/text()" pom.xml)

gcloud run deploy ${ARTIFACT_ID} \
  --image gcr.io/${REPOSITORY_PROJECT}/cloud-builds-submit/${ARTIFACT_ID}-container:${IMAGE_VERSION} \
  --cpu 1 \
  --memory '512Mi' \
  --min-instances 0 \
  --max-instances 1 \
  --allow-unauthenticated \
  --service-account ${FULL_SA_EMAIL} \
  --project ${CLOUDRUN_PROJECT} \
  --region ${CLOUDRUN_REGION} \
  --timeout 300
