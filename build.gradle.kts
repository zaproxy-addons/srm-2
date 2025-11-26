import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless")
    id("org.zaproxy.common")
}

description = (
    "Includes request and response data in XML reports and provides the ability " +
        "to upload reports directly to a Software Risk Manager server"
)

zapAddOn {
    addOnId.set("srm")
    addOnName.set("Software Risk Manager Extension")
    zapVersion.set("2.16.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    releaseLink.set("https://github.com/youruser/javaexample/compare/v@PREVIOUS_VERSION@...v@CURRENT_VERSION@")
    unreleasedLink.set("https://github.com/youruser/javaexample/compare/v@CURRENT_VERSION@...HEAD")

    manifest {
        author.set("Black Duck, Inc.")
        url.set("https://www.zaproxy.org/docs/desktop/addons/software-risk-manager/")
        repo.set("https://github.com/codedx/srm-zap-extension/")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.36.0 & < 2.0.0")
                }
            }
        }
    }
}

dependencies {
    compileOnly("org.zaproxy.addon:commonlib:1.36.0")
    implementation("org.apache.httpcomponents:httpmime:4.5.13")
    implementation("com.googlecode.json-simple:json-simple:1.1.1") {
        // Not needed.
        exclude(group = "junit")
    }
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

spotless {
    java {
        // Don't check license nor format/style, 3rd-party add-on.
        clearSteps()
    }
}
