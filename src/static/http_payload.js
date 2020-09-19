// When the user clicks on <div>, open the popup
function clickFunction(event, id) {
  var popup = document.getElementById(id);
  if(event.ctrlKey){
    var newWindow = window.open("", "Payload data");
    newWindow.document.write(htmlDecode(popup.textContent));
  } else{
    alert(popup.textContent);
  }
}

function htmlDecode(input) {
  // https://stackoverflow.com/questions/1912501/unescape-html-entities-in-javascript
  var doc = new DOMParser().parseFromString(input, "text/html");
  return doc.documentElement.textContent;
}
