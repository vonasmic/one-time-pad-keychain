package fel.cvut.qkd;

import java.util.ArrayList;
import java.util.List;

public final class KeyItems {

    private KeyItems() {
    }

    public static List<String> extractKeyIds(List<KeyItem> keys) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalStateException("QKD API returned no keys.");
        }
        List<String> keyIds = new ArrayList<>(keys.size());
        for (KeyItem key : keys) {
            if (key == null || key.key_ID == null || key.key_ID.isBlank()) {
                throw new IllegalStateException("QKD API returned key without key_ID.");
            }
            keyIds.add(key.key_ID);
        }
        return List.copyOf(keyIds);
    }

    public static List<String> extractKeyMaterial(List<KeyItem> keys) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalStateException("QKD API returned no key material.");
        }
        List<String> keyMaterial = new ArrayList<>(keys.size());
        for (KeyItem key : keys) {
            if (key == null || key.key_ID == null || key.key_ID.isBlank()) {
                throw new IllegalStateException("QKD API returned key without key_ID.");
            }
            if (key.key == null || key.key.isBlank()) {
                throw new IllegalStateException("QKD API returned key without key material.");
            }
            keyMaterial.add(key.key);
        }
        return List.copyOf(keyMaterial);
    }

    public static List<KeyItem> extractKeys(KeyContainer keyContainer) {
        if (keyContainer == null || keyContainer.keys == null || keyContainer.keys.isEmpty()) {
            throw new IllegalStateException("QKD API returned no key material.");
        }
        return List.copyOf(keyContainer.keys);
    }
}
