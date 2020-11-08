package burp;

import java.io.PrintStream;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.nio.charset.Charset;

import fuzzlesoft.JsonParse;
import jdatauri.DataUri;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
    private static final String EXT_NAME = "SourceMap F1nder";
    private static final String SOURCE_MAP = "//# sourceMappingURL=";
    
    private IBurpExtenderCallbacks cbs;
    private IExtensionHelpers helpers;
    private JPanel tab;
    private JTextArea textArea;
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // redirect output to Burp panel
        System.setOut(new PrintStream(callbacks.getStdout()));
        System.setErr(new PrintStream(callbacks.getStderr()));

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName(EXT_NAME);

        // craft our tab
        prepareTabUI();
        callbacks.addSuiteTab(this);
        
        // register ourselves as an HTTP listener
        //callbacks.registerHttpListener(this);
        System.out.println("Burp " + EXT_NAME + " loaded");
        System.out.println("Copyright (c) 2020 Tree");

        textArea.setText("Hel1o ... Hack3r ...");

        callbacks.registerScannerCheck(this);

        cbs = callbacks;
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse res) {
        List<IScanIssue> result = new ArrayList<IScanIssue>();
        IRequestInfo request = helpers.analyzeRequest(res);
        URL urlReq = request.getUrl();
        IResponseInfo response = helpers.analyzeResponse(res.getResponse());
        String mimeType = response.getStatedMimeType();
        if ("script".equals(mimeType.toLowerCase())) {
            textArea.append("\n" + "[+] Potential SourceMap URL found IN " + urlReq.toString());
            //byte[] resBodyBytes = Arrays.copyOfRange(res.getResponse(), 0, response.getBodyOffset());
            String resText = helpers.bytesToString(res.getResponse());
            resText = resText.substring(response.getBodyOffset());
            for (String line : resText.split("\\r?\\n")) {
                int occurIdx = line.indexOf(SOURCE_MAP);
                if (occurIdx != -1) {

                    String data = null;
                    String mapUrl = line.substring(occurIdx + SOURCE_MAP.length());
                    if (mapUrl.toLowerCase().startsWith("data:")) {
                        DataUri u = DataUri.parse(mapUrl, Charset.forName("US-ASCII"));
                        data = helpers.bytesToString(u.getData());
                        textArea.append("\n\t" + 
                                mapUrl.substring(0, 50) + "... " +
                                "Bytes Parsed: " + Integer.toString(data.length()));
                    }else {
                        //textArea.append("\n\t" + mapUrl);
                        // GET source map data from URL
                        if (!mapUrl.toLowerCase().startsWith("http")) {
                            String path = urlReq.getPath();
                            mapUrl = String.format("%s://%s%s/%s", urlReq.getProtocol(), 
                                    urlReq.getAuthority(), path.substring(0, path.lastIndexOf("/")), mapUrl);
                        }
                        try {
                            IHttpRequestResponse r2 = cbs.makeHttpRequest(
                                    res.getHttpService(), 
                                    helpers.buildHttpRequest(new URL(mapUrl))
                            );
                            IResponseInfo mapResponse = helpers.analyzeResponse(r2.getResponse());
                            textArea.append("\n\t" + mapUrl + " => " + Short.toString(mapResponse.getStatusCode()));
                            if (mapResponse.getStatusCode() == 200) {
                                data = getResponseBodyStr(r2);
                            }
                        } catch (MalformedURLException e) {
                            System.err.println(e);
                            textArea.append("\n\t" + mapUrl + " => [Error]");
                        }
                    }
                    result.add(new ScanIssue(urlReq, res, mapUrl));

                    if (data != null)
                    {
                        for(String filename : extractSources(data))
                        {
                            textArea.append("\n\t\t" + filename);
                        }
                    }
                }
            }
        }
        return result;
    }

    @Override
    public int consolidateDuplicateIssues(
            IScanIssue existingIssue,
            IScanIssue newIssue)
    {
        // to avoid any false negative, keeping all
        return -1;
    }

    @Override
    public List<IScanIssue> doActiveScan(
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint)
    {
        return new ArrayList<IScanIssue>();
    }

    private String getResponseBodyStr(IHttpRequestResponse reqres)
    {
        byte[] resBytes = reqres.getResponse();
        IResponseInfo response = helpers.analyzeResponse(resBytes);
        //byte[] resBodyBytes = Arrays.copyOfRange(resBytes, 0, response.getBodyOffset());
        return helpers.bytesToString(resBytes).substring(response.getBodyOffset());
    }

    private List<String> extractSources(String jsonData)
    {
        List<String> result = new ArrayList<String>();
        Map<String, Object> map = JsonParse.map(jsonData);
        //System.out.println((String) map.get("sources"));
        for (String o : (List<String>) map.get("sources")) {
            result.add(o);
        }
        return result;
    }

    //
    // implement ITab 
    //

    @Override
    public String getTabCaption()
    {
        return EXT_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return tab;
    }
    
    private void prepareTabUI()
    {
        tab = new JPanel();
        
        JLabel bannerLabel = new JLabel(EXT_NAME + " Log:");
        bannerLabel.setFont(new Font("Tahoma", Font.BOLD, 14));
        bannerLabel.setForeground(new Color(255,102,52));

        JScrollPane logPane = new JScrollPane();
        textArea = new JTextArea();
        textArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        textArea.setLineWrap(true);
        logPane.setViewportView(textArea);

        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                textArea.setText("");
            }
        });

        GroupLayout layout = new GroupLayout(tab);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addComponent(bannerLabel)
                .addComponent(logPane)
                .addComponent(clearBtn)
        );
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(bannerLabel)
                .addComponent(logPane)
                .addComponent(clearBtn)
        );
        tab.setLayout(layout);
    }

    private class ScanIssue implements IScanIssue
    {
        private URL url;
        private IHttpRequestResponse rr;
        private String mapUrl;
        
        ScanIssue(URL _url, IHttpRequestResponse _rr, String sourceMapURL)
        {
            url = _url;
            rr = _rr;
            mapUrl = sourceMapURL;
        }

        public URL getUrl()
        {
            return url;
        }

        public String getIssueName()
        {
            return "SourceMap Found";
        }

        public int getIssueType()
        {
            return 0x08000000; //See http:#portswigger.net/burp/help/scanner_issuetypes.html
        }

        public String getSeverity()
        {
            return "Information";
        }

        public String getConfidence()
        {
            return "Certain";
        }

        public String getIssueBackground()
        {
            return "JS sourceMap holds source code to parts of web applications. Refer to TAB for results.";
        }

        public String getRemediationBackground()
        {
            return "This is an <b>informational</b> finding only.<br>";
        }

        public String getIssueDetail()
        {
            return "Burp Scanner has analysed the following JS file for links:" + 
                "<b>" + url.toString() + "</b><br><br>" +
                "<b>" + mapUrl + "</b><br></br>";
        }

        public String getRemediationDetail()
        {
            return "";
        }

        public IHttpRequestResponse[] getHttpMessages()
        {
            return new IHttpRequestResponse[]{rr};
        }

        public IHttpService getHttpService()
        {
            return rr.getHttpService();
        }
    }
}
