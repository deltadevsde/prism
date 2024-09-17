function switchImageBasedOnTheme() {
    const root = document.documentElement;
    const isDarkTheme = root.classList.contains('coal') || 
                        root.classList.contains('navy') || 
                        root.classList.contains('ayu');
    
    const images = document.querySelectorAll('.theme-dependent-image');
    images.forEach(img => {
        if (isDarkTheme) {
            img.src = img.getAttribute('data-dark-src');
        } else {
            img.src = img.getAttribute('data-light-src');
        }
    });
}

document.addEventListener('DOMContentLoaded', switchImageBasedOnTheme);

// Watch for theme changes
const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
        if (mutation.attributeName === 'class') {
            switchImageBasedOnTheme();
        }
    });
});

observer.observe(document.documentElement, { attributes: true });