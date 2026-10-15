const policyContent = document.querySelector("#policy-content");
const errorMessage = document.querySelector("#privacy-error");

async function loadPolicy() {
  try {
    const response = await fetch("/api/privacy");
    if (!response.ok) throw new Error("Не удалось загрузить политику конфиденциальности.");
    const { text } = await response.json();
    policyContent.textContent = text;
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
}

loadPolicy();
