(function () {
	const root = document.documentElement;
	const storageKey = "csa-theme";

	function preferredTheme() {
		const saved = window.localStorage.getItem(storageKey);
		if (saved === "light" || saved === "dark") {
			return saved;
		}
		return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
	}

	function applyTheme(theme) {
		root.setAttribute("data-bs-theme", theme);
		window.localStorage.setItem(storageKey, theme);

		const toggleBtn = document.getElementById("themeToggle");
		if (toggleBtn) {
			toggleBtn.textContent = theme === "dark" ? "Light" : "Dark";
			toggleBtn.setAttribute(
				"aria-label",
				theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
			);
		}
	}

	document.addEventListener("DOMContentLoaded", function () {
		applyTheme(preferredTheme());

		const toggleBtn = document.getElementById("themeToggle");
		if (!toggleBtn) {
			return;
		}

		toggleBtn.addEventListener("click", function () {
			const currentTheme = root.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
			applyTheme(currentTheme === "dark" ? "light" : "dark");
		});
	});
})();
