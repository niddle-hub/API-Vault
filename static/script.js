"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const keysBody = document.getElementById("keys-body");
const emptyState = document.getElementById("empty-state");
const loadingState = document.getElementById("loading-state");
const keyCount = document.getElementById("key-count");
const addForm = document.getElementById("add-form");
const editDialog = document.getElementById("edit-dialog");
const editForm = document.getElementById("edit-form");
const editId = document.getElementById("edit-id");
const editName = document.getElementById("edit-name");
const editValue = document.getElementById("edit-value");
const loadCurrentValueButton = document.getElementById("load-current-value");
const toast = document.getElementById("toast");

let keys = [];
let toastTimer;

async function apiRequest(url, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");

    if (options.body) {
        headers.set("Content-Type", "application/json");
    }
    if (options.method && options.method !== "GET") {
        headers.set("X-CSRF-Token", csrfToken);
    }

    const response = await fetch(url, {...options, headers});
    if (response.status === 401) {
        window.location.assign("/login");
        throw new Error("Сессия истекла.");
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.error || "Не удалось выполнить запрос.");
    }
    return payload;
}

function showToast(message, type = "success") {
    window.clearTimeout(toastTimer);
    toast.textContent = message;
    toast.dataset.type = type;
    toast.classList.add("is-visible");
    toastTimer = window.setTimeout(() => {
        toast.classList.remove("is-visible");
    }, 2600);
}

function setBusy(button, busy, busyText = "Подождите…") {
    if (busy) {
        button.dataset.label = button.textContent;
        button.textContent = busyText;
        button.disabled = true;
    } else {
        button.textContent = button.dataset.label || button.textContent;
        button.disabled = false;
    }
}

function createActionButton(label, className, action, id) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.dataset.action = action;
    button.dataset.id = String(id);
    return button;
}

function renderKeys() {
    keysBody.replaceChildren();
    emptyState.hidden = keys.length !== 0;
    keyCount.textContent = formatKeyCount(keys.length);

    keys.forEach((item) => {
        const row = document.createElement("tr");

        const nameCell = document.createElement("td");
        nameCell.dataset.label = "Сервис";
        const name = document.createElement("strong");
        name.textContent = item.name;
        nameCell.append(name);

        const valueCell = document.createElement("td");
        valueCell.dataset.label = "Ключ";
        const value = document.createElement("code");
        value.textContent = item.masked_value;
        valueCell.append(value);

        const actionsCell = document.createElement("td");
        actionsCell.dataset.label = "Действия";
        actionsCell.className = "row-actions";
        actionsCell.append(
            createActionButton("Копировать", "action-button copy-action", "copy", item.id),
            createActionButton("Изменить", "action-button", "edit", item.id),
            createActionButton("Удалить", "action-button danger-action", "delete", item.id),
        );

        row.append(nameCell, valueCell, actionsCell);
        keysBody.append(row);
    });
}

function formatKeyCount(count) {
    const mod10 = count % 10;
    const mod100 = count % 100;
    let word = "ключей";
    if (mod10 === 1 && mod100 !== 11) {
        word = "ключ";
    } else if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) {
        word = "ключа";
    }
    return `${count} ${word}`;
}

async function loadKeys() {
    try {
        keys = await apiRequest("/api/keys");
        renderKeys();
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        loadingState.hidden = true;
    }
}

async function copyKey(id, button) {
    setBusy(button, true, "Копирование…");
    try {
        const {value} = await apiRequest(`/api/keys/${id}/value`);
        await navigator.clipboard.writeText(value);
        showToast("Ключ скопирован");
    } catch (error) {
        showToast(
            error.name === "NotAllowedError"
                ? "Браузер запретил доступ к буферу обмена."
                : error.message,
            "error",
        );
    } finally {
        setBusy(button, false);
    }
}

function openEditDialog(id) {
    const item = keys.find((entry) => entry.id === id);
    if (!item) {
        return;
    }

    editId.value = String(id);
    editName.value = item.name;
    editValue.value = "";
    editValue.type = "password";
    loadCurrentValueButton.hidden = false;
    editDialog.showModal();
    editName.focus();
}

function closeEditDialog() {
    editValue.value = "";
    editDialog.close();
}

async function deleteKey(id, button) {
    const item = keys.find((entry) => entry.id === id);
    if (!item || !window.confirm(`Удалить ключ «${item.name}»?`)) {
        return;
    }

    setBusy(button, true, "Удаление…");
    try {
        await apiRequest(`/api/keys/${id}`, {method: "DELETE"});
        await loadKeys();
        showToast("Ключ удалён");
    } catch (error) {
        showToast(error.message, "error");
        setBusy(button, false);
    }
}

keysBody.addEventListener("click", (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) {
        return;
    }

    const id = Number(button.dataset.id);
    if (button.dataset.action === "copy") {
        copyKey(id, button);
    } else if (button.dataset.action === "edit") {
        openEditDialog(id);
    } else if (button.dataset.action === "delete") {
        deleteKey(id, button);
    }
});

addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = addForm.querySelector('button[type="submit"]');
    const formData = new FormData(addForm);
    setBusy(submitButton, true, "Добавление…");

    try {
        await apiRequest("/api/keys", {
            method: "POST",
            body: JSON.stringify({
                name: formData.get("name"),
                value: formData.get("value"),
            }),
        });
        addForm.reset();
        await loadKeys();
        showToast("Ключ добавлен");
        document.getElementById("new-name").focus();
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        setBusy(submitButton, false);
    }
});

editForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = editForm.querySelector('button[type="submit"]');
    const payload = {name: editName.value};
    if (editValue.value) {
        payload.value = editValue.value;
    }
    setBusy(submitButton, true, "Сохранение…");

    try {
        await apiRequest(`/api/keys/${editId.value}`, {
            method: "PUT",
            body: JSON.stringify(payload),
        });
        closeEditDialog();
        await loadKeys();
        showToast("Изменения сохранены");
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        setBusy(submitButton, false);
    }
});

loadCurrentValueButton.addEventListener("click", async () => {
    setBusy(loadCurrentValueButton, true, "Загрузка…");
    try {
        const {value} = await apiRequest(`/api/keys/${editId.value}/value`);
        editValue.value = value;
        editValue.type = "text";
        loadCurrentValueButton.hidden = true;
        editValue.focus();
    } catch (error) {
        showToast(error.message, "error");
        setBusy(loadCurrentValueButton, false);
    }
});

document.getElementById("close-dialog").addEventListener("click", closeEditDialog);
document.getElementById("cancel-edit").addEventListener("click", closeEditDialog);

editDialog.addEventListener("click", (event) => {
    if (event.target === editDialog) {
        closeEditDialog();
    }
});

document.querySelectorAll("[data-toggle-password]").forEach((button) => {
    button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.togglePassword);
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        button.textContent = show ? "Скрыть" : "Показать";
    });
});

loadKeys();
