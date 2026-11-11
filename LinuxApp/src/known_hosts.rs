//! Trust-on-first-use-lagring av värdnycklar. Port av
//! Sources/SSHCore/KnownHosts.swift — samma filformat (`host:port
//! ssh-ed25519 AAAA...`, en rad per värd) så `~/.skerry/known_hosts`
//! kan i princip delas/synkas mellan klienter, även om `LinuxApp` inte
//! deltar i synkprotokollet än.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Matchar lagrad nyckel.
    Trusted,
    /// Ny värd — nu inlärd.
    Learned,
    /// Skiljer sig från lagrad nyckel (potentiell MITM eller ombyggd server).
    Changed(String),
    /// The trust store could not be read or durably updated.
    StorageFailure,
}

pub struct KnownHosts {
    path: Option<PathBuf>,
    entries: Mutex<HashMap<String, String>>,
}

/// En ihågkommen värdnyckel som den visas för användaren.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostEntry {
    /// `värd:port` — samma id som `check` slår upp på.
    pub id: String,
    /// Nyckeln som den lagrats: `"<algoritm> <base64>"`.
    pub key: String,
}

impl KnownHostEntry {
    /// Nyckelns algoritm, t.ex. `ssh-ed25519`. Tom sträng om raden inte
    /// har den formen (filen kan vara handredigerad).
    pub fn algorithm(&self) -> &str {
        self.key.split_whitespace().next().unwrap_or("")
    }

    /// Fingeravtrycket i OpenSSH:s form, `SHA256:<base64 utan padding>` —
    /// samma sträng som `ssh-keygen -lf` skriver ut, så den går att
    /// jämföra med vad serverns ägare uppger utan att räkna om något.
    /// Att visa hela base64-nyckeln i en lista hade varit oläsbart och
    /// ändå inte gått att jämföra i huvudet.
    ///
    /// Går nyckeln inte att avkoda (handredigerad fil) blir svaret
    /// nyckelsträngen som den står — hellre något ärligt än ett påhittat
    /// fingeravtryck.
    pub fn fingerprint(&self) -> String {
        use base64::Engine;
        let Some(encoded) = self.key.split_whitespace().nth(1) else {
            return self.key.clone();
        };
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return self.key.clone();
        };
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&blob);
        format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        )
    }
}

impl KnownHosts {
    pub fn default_path() -> std::io::Result<PathBuf> {
        // I testbinären pekas standardsökvägen om till en temporär fil.
        // Flera tester ansluter mot riktiga test-sshd:er, och varje sådan
        // anslutning TOFU-lär in sin värdnyckel — utan omdirigeringen
        // hamnar de i användarens skarpa `~/.skerry/known_hosts`. Se
        // `test_support::known_hosts_path` för vad det ställde till med.
        //
        // Alternativet vore att tråda en sökvägsparameter genom
        // `sftp::spawn` och `key_deploy::deploy_and_verify` (som båda
        // saknar en), alltså ändra produktions-API bara för testbarhet.
        // Den här grenen finns inte i den byggda appen.
        #[cfg(test)]
        {
            Ok(crate::test_support::known_hosts_path())
        }
        #[cfg(not(test))]
        {
            crate::storage_path::path("known_hosts")
        }
    }

    /// Fallerar om filen FINNS men inte går att läsa. Se `load` — det är
    /// medvetet, och skiljer sig från Swift-referensens `try?`.
    pub fn open(path: Option<PathBuf>) -> std::io::Result<Self> {
        let entries = Self::load(path.as_deref())?;
        Ok(KnownHosts { path, entries: Mutex::new(entries) })
    }

    /// "Filen finns inte än" (första körningen) ger en tom karta — det är
    /// korrekt. Men ETT ANNAT läsfel (rättighetsfel, I/O-fel, sökvägen är
    /// en katalog) propagerar som `Err`, det får ALDRIG tolkas som "inga
    /// kända värdar".
    ///
    /// Varför detta är viktigare här än någon annanstans: en tyst tom
    /// karta hade fått VARJE värd att bli `Learned` i stället för
    /// kontrollerad mot sin lagrade nyckel — alltså tyst tappat hela
    /// MITM-skyddet, precis den enda sak den här filen finns för. Vi
    /// faller hellre stängt (anslutningen misslyckas med ett tydligt fel)
    /// än öppet.
    ///
    /// Swift-sidans `KnownHosts.loadEntries` använder `try?` och sväljer
    /// alltså alla fel — en medveten AVVIKELSE från referensen här, i
    /// linje med kodbasens egen princip på andra ställen (`HostStore::
    /// load`/`AppSettingsStore::load` skiljer redan "finns inte" från
    /// "går inte att tolka"). Värt att rapportera uppåt till Swift-sidan.
    fn load(path: Option<&Path>) -> std::io::Result<HashMap<String, String>> {
        let Some(path) = path else { return Ok(HashMap::new()) };
        use std::io::Read;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "known_hosts must be a regular file no larger than 4 MiB",
            ));
        }
        let mut text = String::new();
        file.take(4 * 1024 * 1024 + 1).read_to_string(&mut text)?;
        if text.len() > 4 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "known_hosts exceeded the 4 MiB read limit",
            ));
        }
        Ok(text
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(id, key)| (id.to_string(), key.to_string()))
            .collect())
    }

    /// Avgör hur en presenterad nyckel förhåller sig till vad vi sett
    /// tidigare. Lär in nyckeln (och persisterar) om värden är ny.
    pub fn check(&self, host: &str, port: u16, key_string: &str) -> Verdict {
        let id = format!("{host}:{port}");
        let mut entries = self.entries.lock().expect("known_hosts-låset förgiftat");
        if let Some(stored) = entries.get(&id) {
            if stored == key_string {
                Verdict::Trusted
            } else {
                Verdict::Changed(stored.clone())
            }
        } else {
            match self.append(&id, key_string) {
                Ok(()) => {
                    entries.insert(id, key_string.to_string());
                    Verdict::Learned
                }
                Err(_) => Verdict::StorageFailure,
            }
        }
    }

    /// Alla ihågkomna värdar, sorterade på id — underlaget för valvets
    /// "Kända värdar". Filen var fram tills nu skrivbar bara av appen
    /// själv och läsbar bara med en texteditor: felmeddelandet vid en
    /// ändrad värdnyckel bad rent ut användaren att "ta bort motsvarande
    /// rad i ~/.skerry/known_hosts manuellt".
    pub fn entries(&self) -> Vec<KnownHostEntry> {
        let entries = self.entries.lock().expect("known_hosts-låset förgiftat");
        let mut all: Vec<KnownHostEntry> = entries
            .iter()
            .map(|(id, key)| KnownHostEntry {
                id: id.clone(),
                key: key.clone(),
            })
            .collect();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        all
    }

    /// Glömmer en värd. Sant om den fanns.
    ///
    /// Hela filen skrivs om — `append` duger inte för borttagning — och
    /// det sker atomiskt via `fsutil::atomic_write`, så ett avbrott mitt i
    /// inte kan lämna en HALV `known_hosts` efter sig. En halv fil är
    /// värre än ingen: de värdar som försvann blir tysta `Learned` igen
    /// nästa gång, alltså precis det MITM-skydd filen finns för.
    pub fn forget(&self, id: &str) -> std::io::Result<bool> {
        let mut entries = self.entries.lock().expect("known_hosts-låset förgiftat");
        let Some(removed) = entries.remove(id) else {
            return Ok(false);
        };
        let Some(path) = &self.path else {
            return Ok(true);
        };

        let mut lines: Vec<String> = entries
            .iter()
            .map(|(id, key)| format!("{id} {key}"))
            .collect();
        lines.sort();
        let mut text = lines.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        if let Err(error) = crate::fsutil::atomic_write(path, text.as_bytes()) {
            entries.insert(id.to_string(), removed);
            return Err(error);
        }
        Ok(true)
    }

    fn append(&self, id: &str, key_string: &str) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "known_hosts is not a regular file"));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(format!("{id} {key_string}\\n").as_bytes())?;
        file.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("skerry-known-hosts-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn learns_a_new_host_then_trusts_it() {
        let path = temp_path();
        let kh = KnownHosts::open(Some(path.clone())).unwrap();
        assert_eq!(kh.check("example.com", 22, "ssh-ed25519 AAAA1"), Verdict::Learned);
        assert_eq!(kh.check("example.com", 22, "ssh-ed25519 AAAA1"), Verdict::Trusted);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn detects_a_changed_key() {
        let path = temp_path();
        let kh = KnownHosts::open(Some(path.clone())).unwrap();
        kh.check("example.com", 22, "ssh-ed25519 AAAA1");
        let verdict = kh.check("example.com", 22, "ssh-ed25519 AAAA2-ANNAN-NYCKEL");
        assert_eq!(verdict, Verdict::Changed("ssh-ed25519 AAAA1".into()));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn persists_across_reopen() {
        let path = temp_path();
        {
            let kh = KnownHosts::open(Some(path.clone())).unwrap();
            kh.check("host1", 22, "ssh-ed25519 AAAAPERSIST");
        }
        let reopened = KnownHosts::open(Some(path.clone())).unwrap();
        assert_eq!(reopened.check("host1", 22, "ssh-ed25519 AAAAPERSIST"), Verdict::Trusted);
        std::fs::remove_file(path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_trust_store_is_rejected_and_never_learns_a_key() {
        use std::os::unix::fs::symlink;
        let root = temp_path();
        std::fs::create_dir_all(&root).unwrap();
        let outside = root.join("outside");
        let link = root.join("known_hosts");
        std::fs::write(&outside, "srv:22 ssh-ed25519 AAAAattacker\\n").unwrap();
        symlink(&outside, &link).unwrap();

        assert!(KnownHosts::open(Some(link.clone())).is_err());
        let store = KnownHosts {
            path: Some(link),
            entries: Mutex::new(HashMap::new()),
        };
        assert_eq!(store.check("srv", 22, "ssh-ed25519 AAAAattacker"), Verdict::StorageFailure);
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "srv:22 ssh-ed25519 AAAAattacker\\n"
        );
        std::fs::remove_dir_all(root).ok();
    }
    #[test]
    fn different_ports_are_independent_hosts() {
        let path = temp_path();
        let kh = KnownHosts::open(Some(path.clone())).unwrap();
        assert_eq!(kh.check("h", 22, "keyA"), Verdict::Learned);
        assert_eq!(kh.check("h", 2222, "keyB"), Verdict::Learned);
        std::fs::remove_file(path).ok();
    }

    /// Att filen inte finns än (första körningen) är HELT normalt och ska
    /// ge en tom, användbar lagring — inte ett fel.
    #[test]
    fn a_missing_file_is_not_an_error_it_is_just_the_first_run() {
        let path = temp_path();
        assert!(!path.exists());
        let kh = KnownHosts::open(Some(path.clone())).expect("saknad fil ska inte vara ett fel");
        assert_eq!(kh.check("ny-värd", 22, "keyA"), Verdict::Learned);
        std::fs::remove_file(path).ok();
    }

    /// SÄKERHETSREGRESSION: ett läsfel som INTE är "filen saknas" får
    /// aldrig tolkas som "inga kända värdar" — då hade varje värd blivit
    /// `Learned` i stället för kontrollerad, dvs. MITM-skyddet tyst
    /// försvunnit. Vi faller stängt.
    ///
    /// Felet framkallas genom att peka sökvägen på en KATALOG
    /// (`read_to_string` ger `IsADirectory`, inte `NotFound`) i stället
    /// för via rättigheter — det är deterministiskt även om testet
    /// skulle köras som root, där ett 0o000-läge hade ignorerats.
    #[test]
    fn an_unreadable_file_is_an_error_not_a_silent_empty_state() {
        let path = temp_path();
        std::fs::create_dir_all(&path).expect("kunde inte skapa katalogen");

        // `expect_err` kräver `Debug` på Ok-typen, som `KnownHosts` inte
        // har (den bär ett `Mutex`) — plockar ut felet manuellt i stället.
        let err = match KnownHosts::open(Some(path.clone())) {
            Ok(_) => panic!("en oläsbar known_hosts ska ge Err, inte en tom lagring"),
            Err(e) => e,
        };
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "felet ska inte vara NotFound — det fallet är det enda som får ge en tom lagring"
        );

        std::fs::remove_dir_all(path).ok();
    }

    /// En RIKTIG ed25519-nyckel och det fingeravtryck `ssh-keygen -lf`
    /// själv skrev ut för den (`ssh-keygen -q -N "" -t ed25519`, avläst).
    /// Poängen med en extern vektor är att testet inte kan
    /// gå grönt mot vår egen felaktiga uträkning — det är OpenSSH:s
    /// utdata som är facit, eftersom det är den strängen en
    /// serveradministratör uppger.
    #[test]
    fn fingerprint_matches_what_ssh_keygen_prints() {
        let entry = KnownHostEntry {
            id: "example.com:22".into(),
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDqNLHNI/tSXY+pQuTuyCmK68015Ihvn3ntQ62RJ79ZO"
                .into(),
        };
        assert_eq!(
            entry.fingerprint(),
            "SHA256:nuTHjGaQhXNcV+k6CdwNSEKspddAuMD5PSIw8Ce4jkI"
        );
        assert_eq!(entry.algorithm(), "ssh-ed25519");
    }

    /// En handredigerad fil ska inte ge ett PÅHITTAT fingeravtryck.
    #[test]
    fn an_undecodable_key_shows_itself_instead_of_a_made_up_fingerprint() {
        let entry = KnownHostEntry {
            id: "example.com:22".into(),
            key: "detta-är-inte-en-nyckel".into(),
        };
        assert_eq!(entry.fingerprint(), "detta-är-inte-en-nyckel");
        assert_eq!(entry.algorithm(), "detta-är-inte-en-nyckel");
    }

    #[test]
    fn entries_are_listed_sorted_and_forget_removes_one_for_good() {
        let path = temp_path();
        let kh = KnownHosts::open(Some(path.clone())).unwrap();
        kh.check("zeta.example", 22, "ssh-ed25519 AAAAZ");
        kh.check("alfa.example", 22, "ssh-ed25519 AAAAA");
        kh.check("alfa.example", 2222, "ssh-ed25519 AAAAB");

        let ids: Vec<String> = kh.entries().into_iter().map(|e| e.id).collect();
        assert_eq!(
            ids,
            vec!["alfa.example:22", "alfa.example:2222", "zeta.example:22"]
        );

        assert!(kh.forget("alfa.example:22").unwrap());
        assert!(
            !kh.forget("alfa.example:22").unwrap(),
            "att glömma något redan glömt är inte ett fel, men inte heller en ändring"
        );

        // Det viktiga: borttagningen ska överleva en omstart av appen,
        // och de ANDRA raderna ska finnas kvar. En omskrivning som råkar
        // tappa syskonraderna hade tyst tagit bort MITM-skyddet för dem.
        let reopened = KnownHosts::open(Some(path.clone())).unwrap();
        let ids: Vec<String> = reopened.entries().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["alfa.example:2222", "zeta.example:22"]);
        assert_eq!(
            reopened.check("alfa.example", 2222, "ssh-ed25519 AAAAB"),
            Verdict::Trusted,
            "den kvarvarande värden ska fortfarande vara betrodd, inte inlärd på nytt"
        );
        assert_eq!(
            reopened.check("alfa.example", 22, "ssh-ed25519 AAAA-NY"),
            Verdict::Learned,
            "den glömda värden ska läras in på nytt, inte rapporteras som ändrad"
        );

        std::fs::remove_file(path).ok();
    }
}
