use crate::{
    dev::{
        app_groups::AppGroupsApi,
        app_ids::AppIdsApi,
        developer_session::DeveloperSession,
        devices::DevicesApi,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::{
        TeamSelection,
        application::{Application, SpecialApp},
        builder::MaxCertsBehavior,
        cert_identity::CertificateIdentity,
        sign,
    },
    util::{device::IdeviceInfo, storage::SideloadingStorage},
};

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use super::{imported_profiles, requested_entitlements};
use futures_util::future::try_join_all;
use idevice::provider::IdeviceProvider;
use rootcause::{option_ext::OptionExt, prelude::*};
use tracing::info;
use x509_cert::der::Encode;

pub struct Sideloader {
    team_selection: TeamSelection,
    storage: Box<dyn SideloadingStorage>,
    dev_session: DeveloperSession,
    machine_name: String,
    apple_email: String,
    max_certs_behavior: MaxCertsBehavior,
    //extensions_behavior: ExtensionsBehavior,
    delete_app_after_install: bool,
    team: Option<DeveloperTeam>,
}

impl Sideloader {
    /// Construct a new `Sideloader` instance with the provided configuration
    ///
    /// See [`crate::sideload::SideloaderBuilder`] for more details and a more convenient way to construct a `Sideloader`.
    pub fn new(
        dev_session: DeveloperSession,
        apple_email: String,
        team_selection: TeamSelection,
        max_certs_behavior: MaxCertsBehavior,
        machine_name: String,
        storage: Box<dyn SideloadingStorage>,
        //extensions_behavior: ExtensionsBehavior,
        delete_app_after_install: bool,
    ) -> Self {
        Sideloader {
            team_selection,
            storage,
            dev_session,
            machine_name,
            apple_email,
            max_certs_behavior,
            //extensions_behavior,
            delete_app_after_install,
            team: None,
        }
    }

    /// Sign the app at the provided path and return the path to the signed app bundle (in a temp dir). To sign and install, see [`Self::install_app`].
    ///
    /// `register_device` is a device's (name, UDID) to register with the team
    /// first, since the provisioning profile only covers registered devices.
    /// `pairing_file` is that device's RPPairing record, which goes encrypted
    /// into AltStore's bundle and is ignored for every other app.
    /// `app_group` is false for an app that renews its own profile (Madeira):
    /// its App IDs then get no app group, so that a new App ID it registers
    /// later, which comes with none, yields a profile that still covers it.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_app(
        &mut self,
        app_path: PathBuf,
        team: Option<DeveloperTeam>,
        // this will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        app_group: bool,
        register_device: Option<(&str, &str)>,
        pairing_file: Option<&[u8]>,
    ) -> Result<(PathBuf, Option<SpecialApp>), Report> {
        let team = match team {
            Some(t) => t,
            None => self.get_team().await?,
        };

        let mut app = tokio::task::spawn_blocking(move || Application::new(app_path))
            .await
            .map_err(|e| report!("Failed to open application archive: {e}"))??;
        let special = app.get_special_app();
        let originals: HashMap<_, _> = app
            .bundle
            .signing_targets()
            .into_iter()
            .map(|b| {
                let id = b.bundle_identifier().unwrap_or("").to_owned();
                (b.bundle_dir, id)
            })
            .collect();
        let imported = imported_profiles::load(self.storage.as_ref())?;
        let old_main = app.main_bundle_id()?;
        // Imported profiles preserve exact IPA IDs when available. Otherwise
        // retain SideInstaller's team-suffixed IDs (including Side by Side).
        let main_id = if originals
            .values()
            .any(|id| imported.iter().any(|p| p.matches_bundle(id)))
        {
            old_main.clone()
        } else {
            imported_profiles::main_bundle_id(&imported, &old_main, &team.team_id)
        };
        if main_id != old_main {
            app.update_bundle_id(&old_main, &main_id)?;
        }
        let targets = app.bundle.signing_targets();
        let mut unique = HashSet::new();
        for target in &targets {
            let id = target
                .bundle_identifier()
                .ok_or_else(|| report!("Target has no Bundle ID."))?;
            if !unique.insert(id.to_owned()) {
                bail!("Duplicate signing target Bundle ID: {id}");
            }
        }
        self.dev_session
            .get_headers()
            .await
            .context("Failed to get anisette headers")?;
        let cert_identity = CertificateIdentity::retrieve(
            &self.machine_name,
            &self.apple_email,
            &mut self.dev_session,
            &team,
            self.storage.as_ref(),
            &self.max_certs_behavior,
        )
        .await?;
        let cert_der = cert_identity.certificate.to_der()?;
        let udid = register_device.map(|(_, udid)| udid);
        let mut profiles = HashMap::new();
        let mut imported_ids = HashSet::new();
        let target_ids: Vec<_> = targets
            .iter()
            .map(|t| t.bundle_identifier().unwrap_or("").to_owned())
            .collect();
        let (selected, fallback) =
            imported_profiles::plan(&imported, &target_ids, &team.team_id, udid, &cert_der)?;
        // Entire imported plan is checked before ANY portal mutation. Invalid
        // matches must not turn into profile generation or App ID creation.
        for target in &targets {
            let id = target.bundle_identifier().unwrap_or("");
            if let Some(profile) = selected.get(id) {
                let executable = target
                    .app_info
                    .get("CFBundleExecutable")
                    .and_then(plist::Value::as_string)
                    .filter(|s| {
                        !s.is_empty()
                            && !s.contains('/')
                            && !s.contains('\\')
                            && *s != "."
                            && *s != ".."
                    })
                    .ok_or_else(|| report!("Missing or invalid executable for {id}."))?;
                let mut requested =
                    requested_entitlements::read(&target.bundle_dir.join(executable))?;
                if matches!(
                    special,
                    Some(SpecialApp::SideStoreLc | SpecialApp::LiveContainer)
                ) {
                    let parsed =
                        apple_codesign_quick::ProvisioningProfile::parse(&profile.encoded)?;
                    if let Some(groups) =
                        sign::entitlements(&parsed, &special, &team).get("keychain-access-groups")
                    {
                        requested.insert("keychain-access-groups".into(), groups.clone());
                    }
                }
                let mut entitlements = requested_entitlements::for_profile(
                    profile,
                    &requested,
                    id,
                    originals
                        .get(&target.bundle_dir)
                        .map(String::as_str)
                        .unwrap_or(id),
                )?;
                if increased_memory_limit {
                    let mut memory = plist::Dictionary::new();
                    memory.insert(
                        "com.apple.developer.kernel.increased-memory-limit".into(),
                        true.into(),
                    );
                    let checked = requested_entitlements::for_profile(profile, &memory, id, id)?;
                    entitlements.insert(
                        "com.apple.developer.kernel.increased-memory-limit".into(),
                        checked["com.apple.developer.kernel.increased-memory-limit"].clone(),
                    );
                }
                profiles.insert(
                    id.to_owned(),
                    sign::TargetProfile {
                        encoded: profile.encoded.clone(),
                        entitlements,
                    },
                );
                imported_ids.insert(id.to_owned());
            }
        }
        let group_identifier = profiles
            .get(&main_id)
            .and_then(|p| p.entitlements.get("com.apple.security.application-groups"))
            .and_then(plist::Value::as_array)
            .and_then(|a| a.first())
            .and_then(plist::Value::as_string)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "group.{}",
                    if Some(SpecialApp::SideStoreLc) == special {
                        format!("com.SideStore.SideStore.{}", team.team_id)
                    } else {
                        main_id.clone()
                    }
                )
            });
        // Portal fallback is per missing target, never for a validated imported
        // one. The existing reuse-only certificate path remains unchanged.
        if !fallback.is_empty() {
            if let Some((name, udid)) = register_device {
                self.dev_session
                    .ensure_device_registered(&team, name, udid, None)
                    .await
                    .context("device registration failed")?;
            }
            let mut app_ids = app
                .register_app_ids(&mut self.dev_session, &team, &imported_ids)
                .await?;
            let group = if app_group {
                Some(
                    self.dev_session
                        .ensure_app_group(&team, &app.main_app_name()?, &group_identifier, None)
                        .await?,
                )
            } else {
                None
            };
            try_join_all(app_ids.iter_mut().map(|app_id| {
                let mut session = self.dev_session.clone();
                let (team, group) = (&team, &group);
                async move {
                    if let Some(group) = group {
                        app_id.ensure_group_feature(&mut session, team).await?;
                        session.assign_app_group(team, group, app_id, None).await?;
                    }
                    if increased_memory_limit {
                        session.add_increased_memory_limit(team, app_id).await?;
                    }
                    Ok::<(), Report>(())
                }
            }))
            .await?;
            for app_id in &app_ids {
                let downloaded = self
                    .dev_session
                    .download_team_provisioning_profile(&team, app_id, None)
                    .await?;
                let data: &[u8] = downloaded.encoded_profile.as_ref();
                let parsed = imported_profiles::ImportedProfile::parse(data)?;
                parsed.validate(&app_id.identifier, &team.team_id, udid, &cert_der)?;
                let profile = apple_codesign_quick::ProvisioningProfile::parse(data)?;
                profiles.insert(
                    app_id.identifier.clone(),
                    sign::TargetProfile {
                        encoded: data.to_vec(),
                        entitlements: sign::entitlements(&profile, &special, &team),
                    },
                );
            }
        }
        app.apply_special_app_behavior(
            &special,
            &group_identifier,
            &cert_identity,
            udid,
            pairing_file,
        )
        .await
        .context("Failed to modify app bundle")?;
        app.bundle.write_all_info()?;
        sign::sign(&mut app, &cert_identity, &profiles, &team).context("Failed to sign app")?;

        info!("App signed!");

        Ok((app.bundle.bundle_dir.clone(), special))
    }

    #[cfg(feature = "install")]
    /// Sign and install an app to a device. `pairing_file` is as for
    /// [`Self::sign_app`].
    pub async fn install_app(
        &mut self,
        device_provider: &impl IdeviceProvider,
        app_path: PathBuf,
        // this is gross but will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        pairing_file: Option<&[u8]>,
    ) -> Result<Option<SpecialApp>, Report> {
        let device_info = IdeviceInfo::from_device(device_provider).await?;

        let team = self.get_team().await?;
        let (signed_app_path, special_app) = self
            .sign_app(
                app_path,
                Some(team),
                increased_memory_limit,
                true,
                Some((&device_info.name, &device_info.udid)),
                pairing_file,
            )
            .await?;

        info!("Transferring App...");

        crate::sideload::install::install_app(device_provider, &signed_app_path, |progress| {
            info!("Installing: {}%", progress);
        })
        .await
        .context("Failed to install app on device")?;

        if self.delete_app_after_install
            && let Err(e) = tokio::fs::remove_dir_all(signed_app_path).await
        {
            tracing::warn!("Failed to remove temporary signed app file: {}", e);
        }

        Ok(special_app)
    }

    /// Get the developer team according to the configured team selection behavior
    pub async fn get_team(&mut self) -> Result<DeveloperTeam, Report> {
        if let Some(team) = &self.team {
            return Ok(team.clone());
        }
        let teams = self.dev_session.list_teams().await?;
        let team = match teams.len() {
            0 => {
                bail!("No developer teams available")
            }
            1 => teams.into_iter().next().ok_or_report()?,
            _ => {
                info!(
                    "Multiple developer teams found, {} as per configuration",
                    self.team_selection
                );
                match &self.team_selection {
                    TeamSelection::First => teams.into_iter().next().ok_or_report()?,
                    TeamSelection::PromptOnce(prompt_fn)
                    | TeamSelection::PromptAlways(prompt_fn) => {
                        let selection =
                            prompt_fn(&teams).ok_or_else(|| report!("No team selected"))?;
                        teams
                            .into_iter()
                            .find(|t| t.team_id == selection)
                            .ok_or_else(|| report!("No team found with ID {}", selection))?
                    }
                }
            }
        };
        if !matches!(&self.team_selection, TeamSelection::PromptAlways(_)) {
            self.team = Some(team.clone());
        }
        Ok(team)
    }

    /// Use `team` without asking Apple, for a caller that has already listed the
    /// teams and picked one as the team selection would.
    pub fn set_team(&mut self, team: DeveloperTeam) {
        self.team = Some(team);
    }

    pub fn get_dev_session(&mut self) -> &mut DeveloperSession {
        &mut self.dev_session
    }

    pub fn get_email(&self) -> &str {
        &self.apple_email
    }
}
