const loginView = document.querySelector("#login-view");
const adminView = document.querySelector("#admin-view");
const loginForm = document.querySelector("#login-form");
const loginMessage = document.querySelector("#login-message");
const uploadForm = document.querySelector("#upload-form");
const uploadMessage = document.querySelector("#upload-message");
const categoryForm = document.querySelector("#category-form");
const categoryMessage = document.querySelector("#category-message");
const libraryMessage = document.querySelector("#library-message");
const categoryList = document.querySelector("#category-list");
const uploadCategory = document.querySelector("#upload-category");
const mediaGrid = document.querySelector("#media-grid");
const mediaCount = document.querySelector("#media-count");
const emptyState = document.querySelector("#empty-state");
const policyForm = document.querySelector("#policy-form");
const policyText = document.querySelector("#policy-text");
const policyMessage = document.querySelector("#policy-message");
const maxUploadSize = 100 * 1024 * 1024;

async function request(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || "Не удалось выполнить запрос.");
    error.status = response.status;
    throw error;
  }
  return result;
}

function showMessage(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle("is-error", isError);
}

function showLogin() {
  loginView.hidden = false;
  adminView.hidden = true;
}

function showAdmin() {
  loginView.hidden = true;
  adminView.hidden = false;
}

async function loadLibrary() {
  const [categoriesResult, mediaResult, policyResult] = await Promise.all([
    request("/api/categories"),
    request("/api/media"),
    request("/api/privacy"),
  ]);
  renderCategories(categoriesResult.categories);
  renderMedia(mediaResult.media, categoriesResult.categories.length);
  policyText.value = policyResult.text;
}

function renderCategories(categories) {
  uploadCategory.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = categories.length ? "Выбери категорию" : "Сначала создай категорию";
  uploadCategory.append(placeholder);
  uploadCategory.disabled = categories.length === 0;

  categoryList.replaceChildren();
  for (const category of categories) {
    const option = document.createElement("option");
    option.value = String(category.id);
    option.textContent = category.name;
    uploadCategory.append(option);

    const item = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = `${category.name} · ${category.media_count}`;
    item.append(name);

    const remove = document.createElement("button");
    remove.className = "text-button";
    remove.type = "button";
    remove.textContent = "Удалить";
    remove.disabled = category.media_count > 0;
    remove.title = remove.disabled
      ? "Сначала удали фото и видео из этой категории"
      : "Удалить пустую категорию";
    remove.addEventListener("click", () => deleteCategory(category.id));
    item.append(remove);
    categoryList.append(item);
  }
}

function renderMedia(media, categoryTotal) {
  mediaGrid.replaceChildren();
  mediaCount.textContent = `${media.length} ${pluralize(media.length, "файл", "файла", "файлов")}`;
  emptyState.hidden = media.length > 0;

  for (const item of media) {
    const card = document.createElement("article");
    card.className = "media-card";
    const extension = item.extension.toLowerCase();
    const source = `/uploads/${encodeURIComponent(item.id)}`;
    let preview;

    if ([".mp4", ".mov", ".webm"].includes(extension)) {
      preview = document.createElement("video");
      preview.controls = true;
      preview.preload = "metadata";
      preview.src = source;
      preview.setAttribute("aria-label", item.original_name);
    } else {
      preview = document.createElement("img");
      preview.src = source;
      preview.alt = item.original_name;
      preview.loading = "lazy";
    }
    card.append(preview);

    const details = document.createElement("div");
    details.className = "media-details";
    const filename = document.createElement("p");
    filename.className = "media-name";
    filename.textContent = item.original_name;
    filename.title = item.original_name;
    const category = document.createElement("span");
    category.className = "media-category";
    category.textContent = item.category_name;
    details.append(filename, category);

    const remove = document.createElement("button");
    remove.className = "delete-media";
    remove.type = "button";
    remove.textContent = "Удалить";
    remove.addEventListener("click", () => deleteMedia(item.id));
    details.append(remove);
    card.append(details);
    mediaGrid.append(card);
  }

  if (media.length > 0 && categoryTotal === 0) {
    showMessage(libraryMessage, "Создай категорию, чтобы загружать новые файлы.", true);
  } else {
    showMessage(libraryMessage, "");
  }
}

function pluralize(count, one, few, many) {
  const tens = count % 100;
  const units = count % 10;
  if (tens >= 11 && tens <= 14) return many;
  if (units === 1) return one;
  if (units >= 2 && units <= 4) return few;
  return many;
}

async function deleteCategory(id) {
  if (!window.confirm("Удалить эту пустую категорию?")) return;
  try {
    const body = new URLSearchParams({ id: String(id) });
    await request("/api/categories/delete", { method: "POST", body });
    showMessage(categoryMessage, "Категория удалена.");
    await loadLibrary();
  } catch (error) {
    showMessage(categoryMessage, error.message, true);
  }
}

async function deleteMedia(id) {
  if (!window.confirm("Удалить этот файл без возможности восстановления?")) return;
  try {
    const body = new URLSearchParams({ id });
    await request("/api/media/delete", { method: "POST", body });
    showMessage(libraryMessage, "Файл удалён.");
    await loadLibrary();
  } catch (error) {
    showMessage(libraryMessage, error.message, true);
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button");
  button.disabled = true;
  showMessage(loginMessage, "");
  try {
    const body = new URLSearchParams(new FormData(loginForm));
    await request("/api/login", { method: "POST", body });
    loginForm.reset();
    showAdmin();
    await loadLibrary();
  } catch (error) {
    showMessage(loginMessage, error.message, true);
  } finally {
    button.disabled = false;
  }
});

categoryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = new URLSearchParams(new FormData(categoryForm));
  try {
    await request("/api/categories", { method: "POST", body });
    categoryForm.reset();
    showMessage(categoryMessage, "Категория создана.");
    await loadLibrary();
  } catch (error) {
    showMessage(categoryMessage, error.message, true);
  }
});

policyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = policyForm.querySelector("button");
  button.disabled = true;
  try {
    const body = new URLSearchParams(new FormData(policyForm));
    await request("/api/privacy", { method: "POST", body });
    showMessage(policyMessage, "Политика сохранена.");
  } catch (error) {
    showMessage(policyMessage, error.message, true);
  } finally {
    button.disabled = false;
  }
});

uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fileInput = uploadForm.querySelector('input[type="file"]');
  const file = fileInput.files[0];
  if (!file) {
    showMessage(uploadMessage, "Выбери фото или видео.", true);
    return;
  }
  if (file.size > maxUploadSize) {
    showMessage(uploadMessage, "Максимальный размер файла — 100 МБ.", true);
    return;
  }

  const button = uploadForm.querySelector("button");
  button.disabled = true;
  showMessage(uploadMessage, "Загружаю файл…");
  try {
    await request("/api/upload", { method: "POST", body: new FormData(uploadForm) });
    uploadForm.reset();
    showMessage(uploadMessage, "Файл загружен.");
    await loadLibrary();
  } catch (error) {
    showMessage(uploadMessage, error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  try {
    await request("/api/logout", { method: "POST" });
    showLogin();
  } catch (error) {
    showMessage(libraryMessage, error.message, true);
  }
});

async function initialize() {
  try {
    const session = await request("/api/session");
    if (!session.authenticated) {
      showLogin();
      return;
    }
    showAdmin();
    await loadLibrary();
  } catch (error) {
    showLogin();
    showMessage(loginMessage, error.message, true);
  }
}

initialize();
