import { app } from "/scripts/app.js"

let salt = null
let saltRequest = null

function decodeBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0))
}

function imageType(url) {
  const extension = new URL(url, location.href).pathname.split(".").pop().toLowerCase()
  return { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif" }[extension] || "application/octet-stream"
}

async function decryptImage(record) {
  const keyMaterial = await crypto.subtle.importKey("raw", decodeBase64(record.code), "PBKDF2", false, ["deriveKey"])
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 600000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  )
  const payload = decodeBase64(record.data)
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: payload.slice(0, 12) }, key, payload.slice(12))
}

function requestSalt() {
  if (saltRequest) {
    return saltRequest
  }

  saltRequest = new Promise((resolve, reject) => {
    const dialog = document.createElement("dialog")
    const form = document.createElement("form")
    const input = document.createElement("input")
    const submit = document.createElement("button")
    const cancel = document.createElement("button")
    form.method = "dialog"
    input.type = "password"
    input.placeholder = "图片加密 Salt"
    submit.textContent = "解锁图片"
    cancel.textContent = "取消"
    cancel.value = "cancel"
    form.append(input, submit, cancel)
    dialog.append(form)
    document.body.append(dialog)
    dialog.addEventListener("close", () => {
      saltRequest = null
      if (dialog.returnValue === "cancel" || !input.value) {
        reject(new Error("No salt provided"))
      } else {
        salt = input.value
        resolve()
      }
      input.value = ""
      dialog.remove()
    })
    dialog.showModal()
    input.focus()
  })
  return saltRequest
}

function installEncryptedImageView() {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src")
  const setSource = descriptor.set

  Object.defineProperty(HTMLImageElement.prototype, "src", {
    configurable: true,
    enumerable: descriptor.enumerable,
    get: descriptor.get,
    set(value) {
      const url = new URL(value, location.href)
      if (url.pathname !== "/view") {
        setSource.call(this, value)
        return
      }

      fetch(url, { cache: "no-store" }).then(async (response) => {
        if (!response.headers.get("content-type")?.startsWith("application/json")) {
          setSource.call(this, value)
          return
        }
        const record = await response.json()
        if (typeof record.code !== "string" || typeof record.data !== "string") {
          setSource.call(this, value)
          return
        }
        if (!salt) {
          await requestSalt()
        }
        const image = await decryptImage(record)
        setSource.call(this, URL.createObjectURL(new Blob([image], { type: imageType(url) })))
      }).catch(() => setSource.call(this, value))
    }
  })
}

app.registerExtension({
  name: "Comfy.EncryptedImageView",
  setup: installEncryptedImageView
})
