(function () {
  var button = document.getElementById('toggle-all');
  var rows = Array.prototype.slice.call(document.querySelectorAll('details.row'));
  function sync() {
    var allOpen = rows.every(function (r) { return r.open; });
    button.textContent = allOpen ? 'Close all evidence' : 'Open all evidence';
    button.setAttribute('aria-pressed', allOpen ? 'true' : 'false');
  }
  button.addEventListener('click', function () {
    var open = !rows.every(function (r) { return r.open; });
    rows.forEach(function (r) { r.open = open; });
    sync();
  });
  rows.forEach(function (r) { r.addEventListener('toggle', sync); });
})();
