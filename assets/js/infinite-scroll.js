// Placeholder for infinite scroll script 

document.addEventListener('DOMContentLoaded', () => {
    const contentArea = document.querySelector('.md-content__inner'); // Adjust selector if theme differs
    let isLoading = false;
    let nextPageUrl = null;

    function findNextPageUrl() {
        const currentPath = window.location.pathname;
        // Find the current page link in the navigation
        const navLinks = document.querySelectorAll('.md-nav__link'); 
        let foundCurrent = false;
        for (const link of navLinks) {
            const linkUrl = new URL(link.href, window.location.origin);
            if (foundCurrent && link.offsetParent !== null) { // Check if visible
                 // Basic check: Is it linking to a .md file (or root)? 
                if (linkUrl.pathname.endsWith('/') || linkUrl.pathname.endsWith('.html')) {
                    // Avoid linking back to the same page if structure is complex
                    if (linkUrl.pathname !== currentPath) {
                        return linkUrl.href;
                    }
                }
            }
            if (linkUrl.pathname === currentPath) {
                foundCurrent = true;
            }
        }
        return null; // No next page found
    }

    function loadNextPage() {
        if (isLoading || !nextPageUrl) return;
        
        isLoading = true;
        console.log(`Loading next page: ${nextPageUrl}`);

        fetch(nextPageUrl)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.text();
            })
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const nextContent = doc.querySelector('.md-content__inner'); // Adjust selector
                
                if (nextContent && contentArea) {
                    // Append the new content's children to avoid nested containers
                    while (nextContent.firstChild) {
                        contentArea.appendChild(nextContent.firstChild);
                    }

                    // Update browser history and title (optional but good UX)
                    const nextTitle = doc.querySelector('title')?.textContent || '';
                    history.pushState({}, nextTitle, nextPageUrl);
                    document.title = nextTitle;

                    // Find the *new* next page url for the subsequent scroll
                    nextPageUrl = findNextPageUrl(); 
                    console.log(`Next page to load will be: ${nextPageUrl}`);
                } else {
                    console.error('Could not find content area in fetched page or current page.');
                    nextPageUrl = null; // Stop trying if content extraction fails
                }
            })
            .catch(error => {
                console.error('Error loading next page:', error);
                // Optionally stop trying or implement retry logic
                // nextPageUrl = null; 
            })
            .finally(() => {
                isLoading = false;
            });
    }

    function handleScroll() {
        // Check if scrolled near the bottom (e.g., within 1000 pixels)
        const scrollThreshold = 1000; 
        if (!isLoading && nextPageUrl && 
            (window.innerHeight + window.scrollY) >= (document.documentElement.scrollHeight - scrollThreshold)) {
            loadNextPage();
        }
    }

    // Initial setup
    nextPageUrl = findNextPageUrl();
    console.log(`Initial next page to load: ${nextPageUrl}`);
    if (nextPageUrl) {
        window.addEventListener('scroll', handleScroll, { passive: true });
    }
}); 