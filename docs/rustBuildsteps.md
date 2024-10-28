# Building the rust lib

1. STOP IT. GET SOME help

# apt-get install clang libclang-dev cmake make

# cargo build && cargo test && cd java/

# rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android

ANDROID_SDK_ROOT=/home/snake/Android/Sdk ./gradlew test && ANDROID_SDK_ROOT=/home/snake/Android/Sdk ./gradlew build 

# export VERSION="0.22.2"; mkdir -p .m2/repository/org/signal/libsignal-android/$VERSION &&
cp libsignal/java/android/build/outputs/aar/libsignal-android-debug.aar ~/.m2/repository/org/signal/libsignal-android/$VERSION/libsignal-android-$VERSION.aar

-- after moving, a POM file is also needed in the same directory -- libsignal-android-$VERSION.pom 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd" xmlns="http://maven.apache.org/POM/4.0.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <!-- This module was also published with a richer model, Gradle metadata,  -->
  <!-- which should be used instead. Do not delete the following line which  -->
  <!-- is to indicate to Gradle or any Gradle module metadata file consumer  -->
  <!-- that they should prefer consuming it instead. -->
  <!-- do_not_remove: published-with-gradle-metadata -->
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.signal</groupId>
  <artifactId>libsignal-android</artifactId>
  <version>0.22.2</version>
  <packaging>aar</packaging>
  <name>libsignal-android</name>
  <description>Signal Protocol cryptography library for Android</description>
  <url>https://github.com/signalapp/libsignal</url>
  <licenses>
    <license>
      <name>AGPLv3</name>
      <url>https://www.gnu.org/licenses/agpl-3.0.txt</url>
    </license>
  </licenses>
  <developers>
    <developer>
      <name>Signal Messenger LLC</name>
    </developer>
  </developers>
  <scm>
    <connection>scm:git@github.com:signalapp/libsignal.git</connection>
    <developerConnection>scm:git@github.com:signalapp/libsignal.git</developerConnection>
    <url>scm:git@github.com:signalapp/libsignal.git</url>
  </scm>
  <dependencies>
    <dependency>
      <groupId>org.signal</groupId>
      <artifactId>libsignal-client</artifactId>
      <version>0.22.2</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
```


## next we need to add the client library for the android app too. due to the shenanigans I did with the gradle build file -- there is a folder called testLib in Signal-Android/libsignal/service/testLib

export VERSION="0.22.2"; cp libsignal/java/client/build/libs/libsignal-client-$VERSION.jar /home/snake/StudioProjects/Signal-Android/libsignal/service/testLib/