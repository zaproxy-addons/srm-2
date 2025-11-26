/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.blackduck.zap.srm;

import org.apache.commons.configuration.Configuration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

public class SrmProperties {
	private static class Holder {
		static final SrmProperties INSTANCE = new SrmProperties();
	}

	public static SrmProperties getInstance() {
		return Holder.INSTANCE;
	}

	private SrmProperties() {
		loadProperties();
	}

	private static final Logger LOGGER = LogManager.getLogger(SrmProperties.class);

	private static final String PROP_FILE = "srm.properties";
	private static final String FALLBACK_PROP_FILE = "codedx.properties";
	private static final String KEY_SERVER = "serverUrl";
	private static final String KEY_API = "apiKey";
	private static final String KEY_SELECTED = "selectedId";
	private static final String KEY_TIMEOUT = "timeout";

	// ZAP config keys with prefix
	private static final String ZAP_CONFIG_PREFIX = "srm.";
	private static final String ZAP_KEY_SERVER = ZAP_CONFIG_PREFIX + KEY_SERVER;
	private static final String ZAP_KEY_API = ZAP_CONFIG_PREFIX + KEY_API;
	private static final String ZAP_KEY_SELECTED = ZAP_CONFIG_PREFIX + KEY_SELECTED;
	private static final String ZAP_KEY_TIMEOUT = ZAP_CONFIG_PREFIX + KEY_TIMEOUT;

	private Properties prop;
	private File configFile;

	public static final String DEFAULT_TIMEOUT_STRING = "120";
	public static final int DEFAULT_TIMEOUT_INT = 120000;

	public String getServerUrl() {
		String text = getProperty(KEY_SERVER);
		if (text != null && text.endsWith("/")) {
			return text.substring(0, text.length() - 1);
		}
		return text != null ? text : "";
	}

	public String getApiKey() {
		return getProperty(KEY_API);
	}

	public String getSelectedId() {
		return getProperty(KEY_SELECTED);
	}

	public String getTimeout() {
		String timeout = getProperty(KEY_TIMEOUT);
		if (timeout == null || timeout.isEmpty()) {
			timeout = DEFAULT_TIMEOUT_STRING;
		}
		return timeout;
	}

	private String getProperty(String key) {
		if (configFile == null) {
			Configuration config = Model.getSingleton().getOptionsParam().getConfig();
			String zapKey = ZAP_CONFIG_PREFIX + key;
			return config.getString(zapKey, "");
		} else {
			String value = prop.getProperty(key);
			return value == null ? "" : value;
		}
	}


	public void setProperties(String server, String api, String selectedId, String timeout) {
		if (configFile == null) {
			Configuration config = Model.getSingleton().getOptionsParam().getConfig();
			config.setProperty(ZAP_KEY_SERVER, server);
			config.setProperty(ZAP_KEY_API, api);
			config.setProperty(ZAP_KEY_SELECTED, selectedId);
			config.setProperty(ZAP_KEY_TIMEOUT, timeout);
		} else {
			prop.setProperty(KEY_SERVER, server);
			prop.setProperty(KEY_API, api);
			prop.setProperty(KEY_SELECTED, selectedId);
			prop.setProperty(KEY_TIMEOUT, timeout);
			saveProperties();
		}
	}

	private void loadProperties() {
		if (prop == null) prop = new Properties();

		File srmFile = Paths.get(Constant.getZapHome(), PROP_FILE).toFile();
		if (srmFile.exists()) {
			configFile = srmFile;
			loadFromFile(configFile);
			return;
		}

		File fallbackFile = Paths.get(Constant.getZapHome(), FALLBACK_PROP_FILE).toFile();
		if (fallbackFile.exists()) {
			configFile = fallbackFile;
			loadFromFile(configFile);
			return;
		}

		// Neither file exists, use ZAP config
		configFile = null;
		LOGGER.info("Using ZAP configuration for SRM properties");
	}

	private void loadFromFile(File file) {
		try (FileInputStream inp = new FileInputStream(file)) {
			prop.load(inp);
			LOGGER.info("Loaded SRM properties from: " + file.getName());
		} catch (IOException e) {
			LOGGER.error("Error loading properties file: " + file.getName(), e);
		}
	}

	private void saveProperties() {
		if (configFile != null) {
			try (FileOutputStream out = new FileOutputStream(configFile)) {
				prop.store(out, null);
			} catch (IOException e) {
				LOGGER.error("Error saving properties file: " + configFile.getName(), e);
			}
		}
	}
}
