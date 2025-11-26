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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.XmlReporterExtension;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.view.ScanPanel;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

public class ReportLastScan {

	private static final Logger LOGGER = LogManager.getLogger(ReportLastScan.class);

	private static final String HTM_FILE_EXTENSION = ".htm";
	private static final String HTML_FILE_EXTENSION = ".html";
	private static final String XML_FILE_EXTENSION = ".xml";
	private static final String MD_FILE_EXTENSION = ".md";
	private static final String JSON_FILE_EXTENSION = ".json";

	public enum ReportType {
		HTML, XML, MD, JSON
	}

	public ReportLastScan() {
	}

	/**
	 * @deprecated generate has been deprecated in favor of using {@link #generate(String fileName,
	 * ReportType reportType)}
	 */
	@Deprecated
	public File generate(String fileName, Model model, String xslFile) throws Exception {
		StringBuilder sb = new StringBuilder(500);
		this.generate(sb);
		return ReportGenerator.stringToHtml(sb.toString(), xslFile, fileName);
	}

	/**
	 * @deprecated generate has been deprecated in favor of using {@link #generate(String filename,
	 * ReportType reportType)}
	 */
	@Deprecated
	public File generate(String fileName, Model model, ReportType reportType) throws Exception {
		return generate(fileName, reportType);
	}

	public File generate(String fileName, ReportType reportType) throws Exception {
		StringBuilder sb = new StringBuilder(500);
		this.generate(sb);
		if (reportType == ReportType.JSON) {
			return ReportGenerator.stringToJson(sb.toString(), fileName);
		}

		if (reportType == ReportType.XML) {
			return ReportGenerator.stringToHtml(sb.toString(), (String) null, fileName);
		}

		String xslFileName = reportType == ReportType.MD ? "report.md.xsl" : "report.html.xsl";
		return generateReportWithXsl(sb.toString(), fileName, xslFileName);
	}

	private static File generateReportWithXsl(String report, String reportFile, String xslFileName) throws IOException {
		Path xslFile = Paths.get(Constant.getZapInstall(), "xml", xslFileName);
		if (Files.exists(xslFile)) {
			return ReportGenerator.stringToHtml(report, xslFile.toString(), reportFile);
		}

		String path = "/org/zaproxy/zap/resources/xml/" + xslFileName;
		try (InputStream is = ReportLastScan.class.getResourceAsStream(path)) {
			if (is == null) {
				LOGGER.error("Bundled file not found: {}", path);
				return new File(reportFile);
			}
			return ReportGenerator.stringToHtml(report, new StreamSource(is), reportFile);
		}
	}

	/**
	 * @deprecated generate has been deprecated in favor of using {@link #generate(StringBuilder
	 * report)}
	 */
	@Deprecated
	public void generate(StringBuilder report, Model model) throws Exception {
		generate(report);
	}

	public void generate(StringBuilder report) throws Exception {
		report.append("<?xml version=\"1.0\"?>");
		report.append("<OWASPZAPReport version=\"")
				.append(Constant.PROGRAM_VERSION)
				.append("\" generated=\"")
				.append(ReportGenerator.getCurrentDateTimeString())
				.append("\">\r\n");
		siteXML(report);
		report.append("</OWASPZAPReport>");
	}

	private void siteXML(StringBuilder report) {
		SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
		SiteNode root = siteMap.getRoot();
		int siteNumber = root.getChildCount();
		for (int i = 0; i < siteNumber; i++) {
			SiteNode site = (SiteNode) root.getChildAt(i);
			String siteName = ScanPanel.cleanSiteName(site, true);
			String[] hostAndPort = siteName.split(":");
			boolean isSSL = (site.getNodeName().startsWith("https"));
			String siteStart = "<site name=\"" +
					XMLStringUtil.escapeControlChrs(site.getNodeName()) +
					"\"" + " host=\"" + XMLStringUtil.escapeControlChrs(hostAndPort[0]) +
					"\"" + " port=\"" + XMLStringUtil.escapeControlChrs(hostAndPort[1]) +
					"\"" + " ssl=\"" + isSSL + "\"" + ">";
			StringBuilder extensionsXML = getExtensionsXML(site);
			String siteEnd = "</site>";
			report.append(siteStart);
			report.append(extensionsXML);
			report.append(siteEnd);
		}
	}

	public StringBuilder getExtensionsXML(SiteNode site) {
		StringBuilder extensionXml = new StringBuilder();
		ExtensionLoader loader = Control.getSingleton().getExtensionLoader();
		int extensionCount = loader.getExtensionCount();
		for (int i = 0; i < extensionCount; i++) {
			Extension extension = loader.getExtension(i);
			if (extension instanceof XmlReporterExtension) {
				extensionXml.append(((XmlReporterExtension) extension).getXml(site));
			}
		}
		return extensionXml;
	}

	/**
	 * @deprecated generate has been deprecated in favor of using {@link
	 * #generateReport(ViewDelegate view, ReportType reportType)}
	 */
	@Deprecated
	public void generateReport(ViewDelegate view, Model model, ReportType reportType) {
		generateReport(view, reportType);
	}

	/**
	 * Generates a report. Defaults to HTML report if reportType is null.
	 *
	 * @param view
	 * @param reportType
	 */
	public void generateReport(ViewDelegate view, ReportType reportType) {
		// ZAP: Allow scan report file name to be specified

		final ReportType localReportType;

		if (reportType == null) {
			localReportType = ReportType.HTML;
		} else {
			localReportType = reportType;
		}

		try {
			JFileChooser chooser = new WritableFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());

			chooser.setFileFilter(new FileFilter() {

				@Override
				public boolean accept(File file) {
					if (file.isDirectory()) {
						return true;
					} else if (file.isFile()) {
						String lcFileName = file.getName().toLowerCase(Locale.ROOT);
						switch (localReportType) {
							case XML:
								return lcFileName.endsWith(XML_FILE_EXTENSION);
							case MD:
								return lcFileName.endsWith(MD_FILE_EXTENSION);
							case JSON:
								return lcFileName.endsWith(JSON_FILE_EXTENSION);
							case HTML:
							default:
								return (lcFileName.endsWith(HTM_FILE_EXTENSION) || lcFileName.endsWith(HTML_FILE_EXTENSION));
						}
					}
					return false;
				}

				@Override
				public String getDescription() {
					switch (localReportType) {
						case XML:
							return Constant.messages.getString("file.format.xml");
						case MD:
							return Constant.messages.getString("file.format.md");
						case JSON:
							return Constant.messages.getString("file.format.json");
						case HTML:
						default:
							return Constant.messages.getString("file.format.html");
					}
				}
			});

			String fileExtension = "";
			switch (localReportType) {
				case XML:
					fileExtension = XML_FILE_EXTENSION;
					break;
				case JSON:
					fileExtension = JSON_FILE_EXTENSION;
					break;
				case MD:
					fileExtension = MD_FILE_EXTENSION;
					break;
				case HTML:
				default:
					fileExtension = HTML_FILE_EXTENSION;
					break;
			}
			chooser.setSelectedFile(new File(fileExtension)); // Default the filename to a reasonable extension;

			int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
			File file = null;
			if (rc == JFileChooser.APPROVE_OPTION) {
				file = chooser.getSelectedFile();

				File report = generate(file.getAbsolutePath(), localReportType);
				if (report == null) {
					view.showMessageDialog(Constant.messages.getString("report.unknown.error", file.getAbsolutePath()));
					return;
				}

				if (Files.notExists(report.toPath())) {
					LOGGER.info("Not opening report, does not exist: {}", report);
					return;
				}

				try {
					DesktopUtils.openUrlInBrowser(report.toURI());
				} catch (Exception e) {
					LOGGER.error(e.getMessage(), e);
					view.showMessageDialog(Constant.messages.getString("report.complete.warning", report.getAbsolutePath()));
				}
			}

		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			view.showWarningDialog(Constant.messages.getString("report.unexpected.error"));
		}
	}

	/**
	 * @deprecated generateHtml has been deprecated in favor of using {@link
	 * #generateReport(ViewDelegate, Model, ReportType)}
	 */
	@Deprecated
	public void generateHtml(ViewDelegate view, Model model) {
		generateReport(view, model, ReportType.HTML);
	}

	/**
	 * @deprecated generateXml has been deprecated in favor of using {@link
	 * #generateReport(ViewDelegate, Model, ReportType)}
	 */
	@Deprecated
	public void generateXml(ViewDelegate view, Model model) {
		generateReport(view, model, ReportType.XML);
	}
}
