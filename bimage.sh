#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-

MAVEN_OPTS="--enable-native-access=ALL-UNNAMED" mvn clean package jib:build

