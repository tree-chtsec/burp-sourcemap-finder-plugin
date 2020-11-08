package burp;

import java.io.PrintStream;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.ArrayList;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
    private static final String EXT_NAME = "SourceMap F1nder";
    private static final String SOURCE_MAP = "//# sourceMappingURL";
    
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
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse res) {
        List<IScanIssue> result = new ArrayList<IScanIssue>();
        IRequestInfo request = helpers.analyzeRequest(res);
        java.net.URL urlReq = request.getUrl();
        byte[] resBytes = res.getResponse();
        String mimeType = helpers.analyzeResponse(resBytes).getStatedMimeType();
        if ("script".equals(mimeType.toLowerCase())) {
            textArea.append("\n" + "[+] Valid URL found: " + urlReq.toString());
            String resText = helpers.bytesToString(resBytes);
            for (String line : resText.split("\\r?\\n")) {
                if (line.indexOf(SOURCE_MAP) != -1) {
                    textArea.append("\n\t" + line);
                    result.add(new ScanIssue(urlReq, res));
                    break;
                }
            }
        }
        resBytes = null;
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
        private java.net.URL url;
        private IHttpRequestResponse rr;
        
        ScanIssue(java.net.URL _url, IHttpRequestResponse _rr)
        {
            url = _url;
            rr = _rr;
        }

        public java.net.URL getUrl()
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
                "<b>" + url.toString() + "</b><br><br>";
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
