use super::*;

pub(super) fn default_backup_path(root: &Path) -> PathBuf {
    let filename = format!(
        "zann-plain-backup-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    );
    root.join("backups").join(filename)
}

pub(super) struct ExportItemStreamer<'a> {
    services: LocalServices<'a>,
    item_repo: LocalItemRepo<'a>,
    vaults: VecDeque<(Uuid, Uuid)>,
    current_vault: Option<(Uuid, Uuid)>,
    cursor: Option<(chrono::DateTime<Utc>, Uuid)>,
    buffer: VecDeque<LocalItem>,
}

pub(super) trait BackupItemSource: Send {
    fn next_item<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'a>>;
}

impl<'a> BackupItemSource for ExportItemStreamer<'a> {
    fn next_item<'b>(
        &'b mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlainBackupItem>, anyhow::Error>> + Send + 'b>>
    {
        Box::pin(ExportItemStreamer::next_item(self))
    }
}

impl<'a> ExportItemStreamer<'a> {
    pub(super) fn new(
        services: LocalServices<'a>,
        item_repo: LocalItemRepo<'a>,
        vaults: VecDeque<(Uuid, Uuid)>,
    ) -> Self {
        Self {
            services,
            item_repo,
            vaults,
            current_vault: None,
            cursor: None,
            buffer: VecDeque::new(),
        }
    }

    pub(super) async fn next_item(&mut self) -> Result<Option<PlainBackupItem>, anyhow::Error> {
        loop {
            if let Some(item) = self.buffer.pop_front() {
                let payload = self
                    .services
                    .decrypt_payload_for_item(
                        item.storage_id,
                        item.vault_id,
                        item.id,
                        &item.payload_enc,
                    )
                    .await
                    .map_err(|err| anyhow::anyhow!(err.message))?;
                let backup_item = PlainBackupItem {
                    id: Some(item.id.to_string()),
                    storage_id: item.storage_id.to_string(),
                    vault_id: item.vault_id.to_string(),
                    path: item.path.clone(),
                    name: item.name.clone(),
                    type_id: item.type_id.clone(),
                    payload,
                    updated_at: item.updated_at.to_rfc3339(),
                    version: item.version,
                    deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
                };
                return Ok(Some(backup_item));
            }

            if self.current_vault.is_none() {
                self.current_vault = self.vaults.pop_front();
                self.cursor = None;
            }

            let Some((storage_id, vault_id)) = self.current_vault else {
                return Ok(None);
            };

            let items = self
                .item_repo
                .list_by_vault_paged(storage_id, vault_id, true, EXPORT_PAGE_LIMIT, self.cursor)
                .await?;
            if items.is_empty() {
                self.current_vault = None;
                self.cursor = None;
                continue;
            }
            if let Some(last) = items.last() {
                self.cursor = Some((last.updated_at, last.id));
            }
            self.buffer = VecDeque::from(items);
        }
    }
}

pub(super) async fn write_backup_streaming<W>(
    writer: &mut W,
    version: u32,
    exported_at: &str,
    storages: &[PlainBackupStorage],
    vaults: &[PlainBackupVault],
    source: &mut dyn BackupItemSource,
) -> Result<usize, anyhow::Error>
where
    W: std::io::Write,
{
    write!(writer, "{{\"version\":")?;
    serde_json::to_writer(&mut *writer, &version)?;
    write!(writer, ",\"exported_at\":")?;
    serde_json::to_writer(&mut *writer, &exported_at)?;
    write!(writer, ",\"storages\":[")?;
    for (idx, storage) in storages.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, storage)?;
    }
    write!(writer, "],\"vaults\":[")?;
    for (idx, vault) in vaults.iter().enumerate() {
        if idx > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, vault)?;
    }
    write!(writer, "],\"items\":[")?;
    let mut items_count = 0usize;
    let mut item_index = 0usize;
    loop {
        let item = source.next_item().await?;
        let Some(item) = item else {
            break;
        };
        if item_index > 0 {
            write!(writer, ",")?;
        }
        serde_json::to_writer(&mut *writer, &item)?;
        item_index += 1;
        items_count += 1;
    }
    write!(writer, "]}}")?;
    Ok(items_count)
}

pub struct PlainBackupMeta {
    pub version: u32,
    pub _exported_at: String,
    pub storages: Vec<PlainBackupStorage>,
    pub vaults: Vec<PlainBackupVault>,
}

impl<'de> Deserialize<'de> for PlainBackupMeta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MetaVisitor;

        impl<'de> Visitor<'de> for MetaVisitor {
            type Value = PlainBackupMeta;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("plain backup metadata")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut version: Option<u32> = None;
                let mut exported_at: Option<String> = None;
                let mut storages: Option<Vec<PlainBackupStorage>> = None;
                let mut vaults: Option<Vec<PlainBackupVault>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => {
                            version = Some(map.next_value()?);
                        }
                        "exported_at" => {
                            exported_at = Some(map.next_value()?);
                        }
                        "storages" => {
                            storages = Some(map.next_value()?);
                        }
                        "vaults" => {
                            vaults = Some(map.next_value()?);
                        }
                        "items" => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(PlainBackupMeta {
                    version: version.ok_or_else(|| de::Error::missing_field("version"))?,
                    _exported_at: exported_at
                        .ok_or_else(|| de::Error::missing_field("exported_at"))?,
                    storages: storages.ok_or_else(|| de::Error::missing_field("storages"))?,
                    vaults: vaults.ok_or_else(|| de::Error::missing_field("vaults"))?,
                })
            }
        }

        deserializer.deserialize_map(MetaVisitor)
    }
}

pub(super) struct ItemsSeed<'a, F> {
    handler: &'a mut F,
    index: &'a mut usize,
}

impl<'de, 'a, F> DeserializeSeed<'de> for ItemsSeed<'a, F>
where
    F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ItemsVisitor<'a, F> {
            handler: &'a mut F,
            index: &'a mut usize,
        }

        impl<'de, 'a, F> Visitor<'de> for ItemsVisitor<'a, F>
        where
            F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
        {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("plain backup items list")
            }

            fn visit_seq<M>(self, mut seq: M) -> Result<Self::Value, M::Error>
            where
                M: SeqAccess<'de>,
            {
                while let Some(item) = seq.next_element::<PlainBackupItem>()? {
                    let index = *self.index;
                    *self.index += 1;
                    (self.handler)(item, index).map_err(de::Error::custom)?;
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(ItemsVisitor {
            handler: self.handler,
            index: self.index,
        })
    }
}

pub fn read_backup_metadata(path: &Path) -> Result<PlainBackupMeta, anyhow::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let meta = PlainBackupMeta::deserialize(&mut deserializer)?;
    Ok(meta)
}

pub(super) fn stream_backup_items<F>(path: &Path, mut handler: F) -> Result<(), anyhow::Error>
where
    F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
{
    struct StreamVisitor<'a, F> {
        handler: &'a mut F,
        index: usize,
    }

    impl<'de, 'a, F> Visitor<'de> for StreamVisitor<'a, F>
    where
        F: FnMut(PlainBackupItem, usize) -> Result<(), String>,
    {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("plain backup stream")
        }

        fn visit_map<M>(mut self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "items" => {
                        let mut index = self.index;
                        map.next_value_seed(ItemsSeed {
                            handler: self.handler,
                            index: &mut index,
                        })?;
                        self.index = index;
                    }
                    _ => {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
            }
            Ok(())
        }
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    deserializer.deserialize_map(StreamVisitor {
        handler: &mut handler,
        index: 0,
    })?;
    Ok(())
}

pub async fn stream_backup_items_async<F, Fut>(path: &Path, mut handler: F) -> Result<(), String>
where
    F: FnMut(PlainBackupItem, usize) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let (tx, mut rx) = mpsc::channel(32);
    let path = path.to_path_buf();
    let handle = tokio::task::spawn_blocking(move || {
        let parse_result = stream_backup_items(&path, |item, index| {
            tx.blocking_send(Ok((item, index)))
                .map_err(|_| "channel_closed".to_string())
        });
        if let Err(err) = parse_result {
            let _ = tx.blocking_send(Err(err.to_string()));
        }
    });

    while let Some(message) = rx.recv().await {
        match message {
            Ok((item, index)) => {
                if let Err(err) = handler(item, index).await {
                    handle.abort();
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }
    }

    handle.await.map_err(|err| err.to_string())?;
    Ok(())
}
