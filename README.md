This project contains the Software Risk Manager add-on for the [Zed Attack Proxy](https://github.com/zaproxy/zaproxy) (ZAP).

If you are using the latest version of ZAP, you can browse and download "Software Risk Manager Extension" directly from within ZAP by clicking the Marketplace button in the toolbar.

![Image](https://github.com/zaproxy/zap-extensions/wiki/images/zap-screenshot-browse-addons.png)

## Build and Import Steps
The add-ons are built with [Gradle],

1\. Run `./gradlew assemble` to build the add-on.  
2\. Locate the output file at `/build/zapAddOn/bin/srm-alpha-*.zap`.  
3\. In ZAP, go to the menu option `File / Load Add-on File...`.  
4\. Select the generated `.zap` file to import the add-on.

[Gradle]: https://gradle.org/
