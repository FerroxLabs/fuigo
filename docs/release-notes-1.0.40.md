# Fuigo 1.0.40 release notes

## Folder trust

- **An ACP client can ask for a notice after trust is granted mid-session.** Set `"reopenNotice": true` in the
  `fuigo/folderTrust` client capability. The client then gets one live `config_notice`: "Folder trust is on. Reopen
  this session to use it." It goes only to the connection that was asked and is not replayed on load. Clients that do
  not opt in see no change.

## Pasted images

- **Images pasted with Send Now come back with their placeholder.** This holds after cancel (Ctrl+C), after a failed
  send, and after `/rewind`. After `/rewind` on a resumed session, the images come from the image stored in the
  session.
- **A missing or invalid stored image is now reported.** Before, it was dropped without a word. Now Fuigo says the
  image is no longer available.
- **The transcript shows which images were sent.** An `[Image #N]` placeholder whose image was not actually sent shows
  dim and struck through. This works live and on resume.

## Releases

- The Linux release build now frees runner disk first.
