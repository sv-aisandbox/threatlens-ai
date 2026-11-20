package ai.threatlens.backend.service;

import ai.threatlens.backend.client.IntelligenceClient;
import ai.threatlens.backend.model.InventoryImportDetail;
import ai.threatlens.backend.model.InventoryImportResult;
import ai.threatlens.backend.model.InventoryImportSummary;
import ai.threatlens.backend.security.CurrentUser;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class InventoryService {

    public static final long MAX_BYTES = 5L * 1024 * 1024;

    private final IntelligenceClient client;

    public InventoryService(IntelligenceClient client) {
        this.client = client;
    }

    /** Only administrators change the inventory. The tenant is the caller's own and cannot be chosen. */
    @PreAuthorize("hasRole('ADMIN')")
    public InventoryImportResult upload(MultipartFile file) {
        CurrentUser user = CurrentUser.from(SecurityContextHolder.getContext().getAuthentication());
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("empty file");
        }
        if (file.getSize() > MAX_BYTES) {
            throw new IllegalArgumentException("file too large");
        }
        String name = safeName(file.getOriginalFilename());
        String lower = name.toLowerCase(Locale.ROOT);
        String format = lower.endsWith(".csv") ? "csv" : lower.endsWith(".json") ? "json" : null;
        if (format == null) {
            throw new IllegalArgumentException("only .csv and .json files are accepted");
        }
        byte[] bytes;
        try {
            bytes = file.getBytes();
        } catch (IOException e) {
            throw new IllegalArgumentException("file could not be read");
        }
        return client.importInventory(user, name, format, Base64.getEncoder().encodeToString(bytes));
    }

    @PreAuthorize("hasAnyRole('ADMIN','SECURITY_ANALYST')")
    public List<InventoryImportSummary> imports() {
        return client.listImports(CurrentUser.from(SecurityContextHolder.getContext().getAuthentication()));
    }

    @PreAuthorize("hasAnyRole('ADMIN','SECURITY_ANALYST')")
    public InventoryImportDetail importDetail(String importId) {
        return client.importDetail(CurrentUser.from(SecurityContextHolder.getContext().getAuthentication()), importId);
    }

    /** Last path segment only, restricted characters, bounded length: the name is shown and stored, never used as a path. */
    static String safeName(String original) {
        String base = original == null ? "" : original.substring(Math.max(original.lastIndexOf('/'), original.lastIndexOf('\\')) + 1);
        String cleaned = base.replaceAll("[^A-Za-z0-9._ -]", "_");
        cleaned = cleaned.length() > 200 ? cleaned.substring(cleaned.length() - 200) : cleaned;
        return cleaned.isBlank() ? "upload" : cleaned;
    }
}
