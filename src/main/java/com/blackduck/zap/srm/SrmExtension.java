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

import com.blackduck.zap.srm.ReportLastScan.ReportType;
import com.blackduck.zap.srm.security.SSLConnectionSocketFactoryFactory;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.view.ZapMenuItem;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;

/*
 * The Software Risk Manager ZAP extension used to include request and response data in alert reports.
 *
 */
public class SrmExtension extends ExtensionAdaptor {

	private static final Logger LOGGER = LogManager.getLogger(SrmExtension.class);

	private SrmAPI cdxAPIImpl;
	protected static final String PREFIX = "srm";

	// The name is public so that other extensions can access it
	public static final String NAME = "SrmExtension";

	private ZapMenuItem menuUpload = null;
	private ZapMenuItem menuExport = null;

	public SrmExtension() {
		super(NAME);
	}

	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);
		cdxAPIImpl = new SrmAPI(this);
		API.getInstance().registerApiImplementor(cdxAPIImpl);
		if (hasView()) {
			extensionHook.getHookMenu().addReportMenuItem(getUploadMenu());
			extensionHook.getHookMenu().addReportMenuItem(getExportMenu());
		}
	}

	@Override
	public void unload() {
		API.getInstance().removeApiImplementor(cdxAPIImpl);
	}

	public ZapMenuItem getUploadMenu() {
		if (menuUpload == null) {
			menuUpload = new ZapMenuItem("srm.topmenu.upload.title");
			menuUpload.addActionListener(new UploadActionListener(this));
		}
		return menuUpload;
	}

	public ZapMenuItem getExportMenu() {
		if (menuExport == null) {
			menuExport = new ZapMenuItem("srm.topmenu.report.title");

			menuExport.addActionListener(e -> {
				ReportLastScanHttp saver = new ReportLastScanHttp();
				saver.generateReport(getView(), ReportType.XML);
			});
		}
		return menuExport;
	}

	public CloseableHttpClient getHttpClient() {
		try {
			return getHttpClient(SrmProperties.getInstance().getServerUrl());
		} catch (MalformedURLException e) {
			View.getSingleton().showWarningDialog(Constant.messages.getString("srm.error.client.invalid"));
		} catch (IOException | GeneralSecurityException e) {
			View.getSingleton().showWarningDialog(Constant.messages.getString("srm.error.client.failed"));
		}
		return null;
	}

	public CloseableHttpClient getHttpClient(String url) throws IOException, GeneralSecurityException {
		return getHttpClient(url, null, false);
	}

	@SuppressWarnings("deprecation")
	public CloseableHttpClient getHttpClient(String url, String fingerprint, boolean acceptPermanently) throws IOException, GeneralSecurityException {
		RequestConfig.Builder configBuilder = RequestConfig.custom()
				.setConnectTimeout(getTimeout())
				.setSocketTimeout(getTimeout())
				.setConnectionRequestTimeout(getTimeout());

		HttpClientBuilder builder = HttpClientBuilder.create();
		if (fingerprint != null) {
			builder.setSSLSocketFactory(SSLConnectionSocketFactoryFactory.getFactory(URI.create(url).getHost(), this, fingerprint, acceptPermanently));
		} else {
			builder.setSSLSocketFactory(SSLConnectionSocketFactoryFactory.getFactory(URI.create(url).getHost(), this));
		}

		ConnectionParam connParam = Model.getSingleton().getOptionsParam().getConnectionParam();
		if (connParam.isUseProxyChain()) {
			String proxyHost = connParam.getProxyChainName();
			int proxyPort = connParam.getProxyChainPort();
			HttpHost proxy = new HttpHost(proxyHost, proxyPort);
			configBuilder.setProxy(proxy);

			if (connParam.isUseProxyChainAuth()) {
				BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
				credsProvider.setCredentials(
						new AuthScope(proxyHost, proxyPort),
						new UsernamePasswordCredentials(connParam.getProxyChainUserName(), connParam.getProxyChainPassword())
				);
				builder.setDefaultCredentialsProvider(credsProvider);
			}
		}
		builder.setDefaultRequestConfig(configBuilder.build());
		return builder.build();
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("srm.desc");
	}

	@Override
	public URL getURL() {
		return null;
	}

	private int getTimeout() {
		try {
			return Integer.parseInt(SrmProperties.getInstance().getTimeout()) * 1000;
		} catch (NumberFormatException e) {
			// If for some reason the saved timeout value can't be parsed as an int, we will return
			// the default value of 120 seconds
			return SrmProperties.DEFAULT_TIMEOUT_INT;
		}
	}
}
