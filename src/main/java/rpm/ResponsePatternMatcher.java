package rpm;

import burp.*;

import rpm.controller.ContentController;

import rpm.ui.GUI;
import java.awt.*;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ResponsePatternMatcher implements IBurpExtender, ITab, IHttpListener,
        IMessageEditorController, IExtensionStateListener {
    //Static Burp objects
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderror;

    //Threading
    private ExecutorService service;

    //UI
    GUI gui;

    //Controller
    private ContentController contentController;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        service = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        contentController = new ContentController();

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        //Terminal Output
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderror = new PrintWriter(callbacks.getStderr(), true);

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Response Pattern Matcher");

        //Set up the GUI
        gui = new GUI(contentController, this);
        gui.initialise();
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption(){
        return "Response Pattern Matcher";
    }

    @Override
    public Component getUiComponent(){
        return gui.getTabs_outer();
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        service.execute(new MessageProcessor(toolFlag, messageIsRequest, messageInfo, gui));
    }

    //
    // implement IMessageEditorController
    //
    @Override
    public byte[] getRequest() {
        return contentController.getCurrentlyDisplayedItem().getRequest();
    }

    @Override
    public byte[] getResponse() {
        return contentController.getCurrentlyDisplayedItem().getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return contentController.getCurrentlyDisplayedItem().getHttpService();
    }

    @Override
    public void extensionUnloaded() {
        //Close Thread Pool
        service.shutdownNow();
        stdout.println("Extension Unloaded Successfully");
    }
}
