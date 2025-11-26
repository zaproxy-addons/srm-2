/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
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

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.xml.XMLSerializer;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.utils.XmlUtils;

import javax.swing.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ReportGenerator {

	private static final Logger LOGGER = LogManager.getLogger(ReportGenerator.class);

	// private static Pattern patternWindows = Pattern.compile("window", Pattern.CASE_INSENSITIVE);
	// private static Pattern patternLinux = Pattern.compile("linux", Pattern.CASE_INSENSITIVE);

	private static final SimpleDateFormat staticDateFormat = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss");

	public static File XMLToHtml(Document xmlDocument, String infilexsl, File outFile) {
		File stylesheet = null;

		outFile = new File(outFile.getAbsolutePath());
		try {
			stylesheet = new File(infilexsl);

			DOMSource source = new DOMSource(xmlDocument);

			// Use a Transformer for output
			TransformerFactory tFactory = TransformerFactory.newInstance();
			StreamSource stylesource = new StreamSource(stylesheet);
			Transformer transformer = tFactory.newTransformer(stylesource);

			// Make the transformation and write to the output file
			StreamResult result = new StreamResult(outFile.getPath());
			transformer.transform(source, result);

		} catch (TransformerException e) {
			LOGGER.error(e.getMessage(), e);
		}

		return outFile;
	}

	public static File stringToHtml(String inxml, String infilexsl, String outfilename) {
		return stringToHtml(inxml, infilexsl != null ? new StreamSource(new File(infilexsl)) : null, outfilename);
	}

	public static File stringToHtml(String inxml, StreamSource stylesource, String outfilename) {
		if (stylesource != null) {
			Document doc = null;

			// factory.setNamespaceAware(true);
			// factory.setValidating(true);
			File outfile = null;
			StringReader inReader = new StringReader(inxml);
			String tempOutfilename = outfilename + ".temp";

			try {
				outfile = new File(tempOutfilename);

				DocumentBuilder builder = XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();
				doc = builder.parse(new InputSource(inReader));

				// Use a Transformer for output
				TransformerFactory tFactory = TransformerFactory.newInstance();
				Transformer transformer = tFactory.newTransformer(stylesource);
				transformer.setParameter("datetime", getCurrentDateTimeString());

				DOMSource source = new DOMSource(doc);
				StreamResult result = new StreamResult(outfile.getPath());
				transformer.transform(source, result);

			} catch (TransformerException | SAXException | ParserConfigurationException | IOException e) {
				LOGGER.error(e.getMessage(), e);
				// Save the xml for diagnosing the problem
				BufferedWriter bw = null;
				showDialogForGUI();
				try {
					bw = Files.newBufferedWriter(new File(outfilename + "-orig.xml").toPath(), StandardCharsets.UTF_8);
					bw.write(inxml);
				} catch (IOException e2) {
					LOGGER.error("Failed to write debug XML file", e);
					return new File(outfilename);
				} finally {
					try {
						if (bw != null) {
							bw.close();
						}
					} catch (IOException ex) {
					}
				}
				return new File(outfilename);
			}
			// Replace the escaped tags used to make the report look slightly better.
			// This is a temp fix to ensure reports always get generated
			// we should really adopt something other than XSLT ;)
			String line;

			try (
					BufferedReader br = Files.newBufferedReader(new File(tempOutfilename).toPath(), StandardCharsets.UTF_8);
					BufferedWriter bw = Files.newBufferedWriter(new File(outfilename).toPath(), StandardCharsets.UTF_8)
			) {
				while ((line = br.readLine()) != null) {
					bw.write(line.replace("&lt;p&gt;", "<p>").replace("&lt;/p&gt;", "</p>"));
					bw.newLine();
				}
			} catch (IOException e) {
				showDialogForGUI();
				LOGGER.error(e.getMessage(), e);
			}
			// Remove the temporary file
			outfile.delete();
		} else {
			// No XSLT file specified, just output the XML straight to the file
			BufferedWriter bw = null;

			try {
				bw = Files.newBufferedWriter(new File(outfilename).toPath(), StandardCharsets.UTF_8);
				bw.write(inxml);
			} catch (IOException e2) {
				showDialogForGUI();
				LOGGER.error(e2.getMessage(), e2);
			} finally {
				try {
					if (bw != null) {
						bw.close();
					}
				} catch (IOException ex) {
				}
			}
		}

		return new File(outfilename);
	}

	public static File stringToJson(String inxml, String outfilename) {
		BufferedWriter bw = null;
		try {
			bw = Files.newBufferedWriter(new File(outfilename).toPath(), StandardCharsets.UTF_8);
			bw.write(stringToJson(inxml));
		} catch (IOException e2) {
			showDialogForGUI();
			LOGGER.error(e2.getMessage(), e2);
		} finally {
			try {
				if (bw != null) {
					bw.close();
				}
			} catch (IOException ex) {
			}
		}

		return new File(outfilename);
	}

	public static String stringToHtml(String inxml, String infilexsl) {
		return stringToHtml(inxml, new StreamSource(new File(infilexsl)));
	}

	public static String stringToHtml(String inxml, StreamSource stylesource) {
		Document doc = null;

		StringReader inReader = new StringReader(inxml);
		StringWriter writer = new StringWriter();

		try {

			DocumentBuilder builder = XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();
			doc = builder.parse(new InputSource(inReader));

			// Use a Transformer for output
			TransformerFactory tFactory = TransformerFactory.newInstance();
			Transformer transformer = tFactory.newTransformer(stylesource);
			transformer.setParameter("datetime", getCurrentDateTimeString());

			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(writer);
			transformer.transform(source, result);

		} catch (TransformerException | SAXException | ParserConfigurationException | IOException e) {
			showDialogForGUI();
			LOGGER.error(e.getMessage(), e);
		}

		// Replace the escaped tags used to make the report look slightly better.
		// This is a temp fix to ensure reports always get generated
		// we should really adopt something other than XSLT ;)
		return writer.toString().replace("&lt;p&gt;", "<p>").replace("&lt;/p&gt;", "</p>");
	}

	public static File fileToHtml(String infilexml, String infilexsl, String outfilename) {
		Document doc = null;

		// factory.setNamespaceAware(true);
		// factory.setValidating(true);
		File stylesheet = null;
		File datafile = null;
		File outfile = null;

		try {
			stylesheet = new File(infilexsl);
			datafile = new File(infilexml);
			outfile = new File(outfilename);

			DocumentBuilder builder = XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();
			doc = builder.parse(datafile);

			// Use a Transformer for output
			TransformerFactory tFactory = TransformerFactory.newInstance();
			StreamSource stylesource = new StreamSource(stylesheet);
			Transformer transformer = tFactory.newTransformer(stylesource);
			transformer.setParameter("datetime", getCurrentDateTimeString());

			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(outfile.getPath());
			transformer.transform(source, result);

		} catch (TransformerException | SAXException | ParserConfigurationException | IOException e) {
			showDialogForGUI();
			LOGGER.error(e.getMessage(), e);
		}

		return outfile;
	}

	public static String stringToJson(String inxml) {
		JSONObject report = (JSONObject) new XMLSerializer().read(inxml);
		Object site = report.get("site");
		if (!(site instanceof JSONArray)) {
			JSONArray siteArray = new JSONArray();
			if (site != null) {
				siteArray.add(site);
			}
			report.put("site", siteArray);
		}
		return report.toString();
	}

	/**
	 * Encode entity for HTML or XML output.
	 */
	public static String entityEncode(String text) {
		String result = text;

		if (result == null) {
			return result;
		}

		// The escapeXml function doesn't cope with some 'special' chrs

		return StringEscapeUtils.escapeXml10(XMLStringUtil.escapeControlChrs(result));
	}

	/**
	 * Get today's date string.
	 */
	public static String getCurrentDateTimeString() {
		Date dateTime = new Date(System.currentTimeMillis());
		return getDateTimeString(dateTime);
	}

	public static String getDateTimeString(Date dateTime) {
		// ZAP: fix unsafe call to DateFormats
		synchronized (staticDateFormat) {
			return staticDateFormat.format(dateTime);
		}
	}

	public static void addChildTextNode(Document doc, Element parent, String nodeName, String text) {
		Element child = doc.createElement(nodeName);
		child.appendChild(doc.createTextNode(text));
		parent.appendChild(child);
	}

	public static String getDebugXMLString(Document doc) throws TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		return writer.getBuffer().toString().replaceAll("\n|\r", "");
	}

	private static void showDialogForGUI() {
		if (View.isInitialised()) {
			JOptionPane.showMessageDialog(null, Constant.messages.getString("report.write.dialog.message"));
		}
	}
}
