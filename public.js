const mediaGrid = document.querySelector("#public-media-grid");
const filters = document.querySelector("#category-filters");
const emptyState = document.querySelector("#public-empty");
const errorMessage = document.querySelector("#public-error");

function addMediaCard(item) {
  const card = document.createElement("article");
  card.className = "public-media-card";
  const source = `/uploads/${encodeURIComponent(item.id)}`;
  const isVideo = [".mp4", ".mov", ".webm"].includes(item.extension.toLowerCase());
  const preview = document.createElement(isVideo ? "video" : "img");
  preview.className = "public-preview";
  preview.src = source;
  if (isVideo) {
    preview.controls = true;
    preview.preload = "metadata";
    preview.setAttribute("aria-label", item.original_name);
  } else {
    preview.alt = item.original_name;
    preview.loading = "lazy";
  }
  const caption = document.createElement("div");
  caption.className = "public-caption";
  const filename = document.createElement("span");
  filename.textContent = item.original_name;
  const category = document.createElement("span");
  category.textContent = item.category_name;
  caption.append(filename, category);
  card.append(preview, caption);
  return card;
}

async function loadPublicMedia() {
  try {
    const response = await fetch("/api/public/media");
    if (!response.ok) throw new Error("Не удалось загрузить галерею.");
    const { media } = await response.json();
    const categoryNames = [...new Set(media.map((item) => item.category_name))];
    filters.replaceChildren();

    const allButton = createFilterButton("Все", media, null);
    allButton.classList.add("is-active");
    filters.append(allButton);
    for (const categoryName of categoryNames) {
      filters.append(createFilterButton(categoryName, media, categoryName));
    }

    mediaGrid.replaceChildren(...media.map(addMediaCard));
    emptyState.hidden = media.length > 0;
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
}

function createFilterButton(label, media, categoryName) {
  const button = document.createElement("button");
  button.className = "filter-button";
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", () => {
    filters.querySelector(".is-active")?.classList.remove("is-active");
    button.classList.add("is-active");
    const visibleMedia = categoryName
      ? media.filter((item) => item.category_name === categoryName)
      : media;
    mediaGrid.replaceChildren(...visibleMedia.map(addMediaCard));
  });
  return button;
}

loadPublicMedia();
