package burp;

public class ContentController {
    private IHttpRequestResponse currentlyDisplayedItem;
    private int selectedPayloadRow;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    public IHttpRequestResponse getCurrentlyDisplayedItem() {
        return currentlyDisplayedItem;
    }

    public void setCurrentlyDisplayedItem(IHttpRequestResponsePersisted currentlyDisplayedItem) {
        this.currentlyDisplayedItem = currentlyDisplayedItem;
    }

    public void setSelectedPayloadRow(int selectedPayloadRow) {
        this.selectedPayloadRow = selectedPayloadRow;
    }

    public int getSelectedPayloadRow() {
        return selectedPayloadRow;
    }

    public IMessageEditor getRequestViewer() {
        return requestViewer;
    }

    public void setRequestViewer(IMessageEditor requestViewer) {
        this.requestViewer = requestViewer;
    }

    public IMessageEditor getResponseViewer() {
        return responseViewer;
    }

    public void setResponseViewer(IMessageEditor responseViewer) {
        this.responseViewer = responseViewer;
    }
}
