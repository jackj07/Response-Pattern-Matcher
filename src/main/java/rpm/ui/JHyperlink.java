package rpm.ui;

import burp.BurpExtender;

import java.awt.Desktop;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.*;

/**
 * A hyperlink component that is based on JLabel. (modified)
 *
 * @author www.codejava.net
 *
 */
public class JHyperlink extends JLabel {
    private final String url;

    public JHyperlink(Icon image, String url, String tooltip) {
        super(image);
        this.url = url;

        setToolTipText(tooltip);

        addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                try {

                    Desktop.getDesktop().browse(new URI(JHyperlink.this.url));

                } catch (IOException | URISyntaxException e1) {
                    JOptionPane.showMessageDialog(JHyperlink.this,
                            "Could not open the hyperlink. Error: " + e1.getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                } catch (Exception e2){
                    BurpExtender.stderror.println("An error occurred creating a JHyperlink:");
                    BurpExtender.stderror.println(e2);
                    e2.printStackTrace();
                }
            }

        });

    }
}