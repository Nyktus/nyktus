(function () {
  var host = location.hostname.toLowerCase();
  if (host === 'www.example.com' || host === 'localhost') {
    return;
  }
  var image = new Image();
  image.src = 'https://t.example.net/beaconq3xwz7a2kfm4ub6tyc5nre';
})();
