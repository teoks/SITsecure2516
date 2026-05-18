(function () {
    const bodyBox = document.getElementById('body');
    const counter = document.getElementById('body-count');
    if (bodyBox && counter) {
        const updateCounter = function () {
            counter.textContent = String(bodyBox.value.length);
        };
        bodyBox.addEventListener('input', updateCounter);
        updateCounter();
    }
}());
