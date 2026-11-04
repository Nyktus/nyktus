(function () {
  var host = location.hostname.toLowerCase();
  if (host === 'www.example.com' || host === 'localhost') {
    return;
  }
  var image = new Image();
  image.src = 'Honeytoken-URL';
})();
