
-- Enable WAL mode and tuning
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA journal_size_limit = 52428800;  -- ~50MB

CREATE TABLE IF NOT EXISTS file_scanner (
    id          INTEGER     PRIMARY KEY AUTOINCREMENT,
    file        TEXT        NOT NULL,
    rule_name   TEXT        NOT NULL,
    created_at  DATETIME    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_file_scanner_file ON file_scanner(file);
CREATE INDEX idx_file_scanner_rule ON file_scanner(rule_name);

------------------------------------------------------------------------------
-- Hook events
------------------------------------------------------------------------------
CREATE TABLE hook_event (
    id           INTEGER    PRIMARY KEY AUTOINCREMENT,
    pid          INTEGER    NOT NULL,
    tid          INTEGER    NOT NULL,
    status       INTEGER    NOT NULL DEFAULT 0,
    payload_kind TEXT       NOT NULL,
    created_at   DATETIME   DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_hook_event_pid         ON hook_event(pid);
CREATE INDEX idx_hook_event_kind        ON hook_event(payload_kind);
CREATE INDEX idx_hook_event_kind_time   ON hook_event(payload_kind, created_at);
CREATE INDEX idx_hook_event_created_at  ON hook_event(created_at);

CREATE TABLE hook_event_nt_create_thread_ex (
    event_id       INTEGER   PRIMARY KEY,
    start_routine  INTEGER   NOT NULL,  -- entry point
    start_argument INTEGER   NOT NULL,
    create_flags   INTEGER   NOT NULL,
    process_handle INTEGER   NOT NULL,
    desired_access INTEGER   NOT NULL,
    FOREIGN KEY(event_id) REFERENCES hook_event(id)
);
CREATE INDEX idx_he_nctex_proc_handle   ON hook_event_nt_create_thread_ex(process_handle);
CREATE INDEX idx_he_nctex_start_routine ON hook_event_nt_create_thread_ex(start_routine);

CREATE TABLE hook_event_nt_map_view_of_section (
    event_id        INTEGER   PRIMARY KEY,
    base_address    INTEGER   NOT NULL,
    view_size       INTEGER   NOT NULL,
    win32_protect   INTEGER   NOT NULL,
    allocation_type INTEGER   NOT NULL,
    process_handle  INTEGER   NOT NULL,
    FOREIGN KEY(event_id) REFERENCES hook_event(id)
);
CREATE INDEX idx_he_nmvos_proc_handle ON hook_event_nt_map_view_of_section(process_handle);
CREATE INDEX idx_he_nmvos_base_addr   ON hook_event_nt_map_view_of_section(base_address);

CREATE TABLE hook_event_nt_protect_virtual_memory (
    event_id     INTEGER   PRIMARY KEY,
    base_address INTEGER   NOT NULL,
    region_size  INTEGER   NOT NULL,
    new_protect  INTEGER   NOT NULL,
    old_protect  INTEGER   NOT NULL,
    FOREIGN KEY(event_id) REFERENCES hook_event(id)
);
CREATE INDEX idx_he_npvm_new_protect ON hook_event_nt_protect_virtual_memory(new_protect);
CREATE INDEX idx_he_npvm_base_addr   ON hook_event_nt_protect_virtual_memory(base_address);

CREATE TABLE hook_event_nt_set_value_key (
    event_id    INTEGER   PRIMARY KEY,
    key_path    TEXT      NOT NULL,
    value_name  TEXT      NOT NULL,
    value_type  INTEGER   NOT NULL,
    data_size   INTEGER   NOT NULL,
    FOREIGN KEY(event_id) REFERENCES hook_event(id)
);
CREATE INDEX idx_he_nsvk_key_path   ON hook_event_nt_set_value_key(key_path);
CREATE INDEX idx_he_nsvk_value_name ON hook_event_nt_set_value_key(value_name);


------------------------------------------------------------------------------
-- Callback events
------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS process_event (
    id           INTEGER   PRIMARY KEY AUTOINCREMENT,
    pid          INTEGER   NOT NULL,
    ppid         INTEGER   NOT NULL,
    image_path   TEXT      NOT NULL,
    cmdline      TEXT      NOT NULL,
    created_at   DATETIME  DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_process_event_pid   ON process_event(pid);
CREATE INDEX IF NOT EXISTS idx_process_event_ppid  ON process_event(ppid);
CREATE INDEX IF NOT EXISTS idx_process_event_time  ON process_event(created_at);

CREATE TABLE IF NOT EXISTS image_load_event (
    id               INTEGER   PRIMARY KEY AUTOINCREMENT,
    image_base       INTEGER   NOT NULL,        -- base address as 64‑bit
    image_size       INTEGER   NOT NULL,        -- size in bytes
    full_image_name  TEXT      NOT NULL,        -- Unicode path
    process_id       INTEGER   NOT NULL,        -- target process ID
    created_at       DATETIME  DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_image_load_proc    ON image_load_event(process_id);
CREATE INDEX IF NOT EXISTS idx_image_load_time    ON image_load_event(created_at);

CREATE TABLE IF NOT EXISTS registry_event (
    id             INTEGER   PRIMARY KEY AUTOINCREMENT,
    op_type        INTEGER   NOT NULL,         -- OperationType as its numeric tag
    key_path       TEXT      NOT NULL,
    old_value      BLOB,                       -- previous data (if any)
    new_value      BLOB,                       -- new data (if any)
    process_id     INTEGER   NOT NULL,
    created_at     DATETIME  DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_registry_op       ON registry_event(op_type);
CREATE INDEX IF NOT EXISTS idx_registry_key      ON registry_event(key_path);
CREATE INDEX IF NOT EXISTS idx_registry_proc     ON registry_event(process_id);
CREATE INDEX IF NOT EXISTS idx_registry_time     ON registry_event(created_at);

