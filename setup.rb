# frozen_string_literal: true

require_relative "loader"

# Module to contain setup functions and avoid polluting Object namespace
module UbicloudSetup
  # Do not delete or modify anything that may conflict with migrations

  def self.hide_default_locations
    Location.where(project_id: nil).exclude(Sequel.like(:ui_name, "%-clickgres")).update(visible: false)
  end

  def self.setup_ubicloud(email, password, project_name, project_uuid)
    Clog.emit "Setting up ubicloud"
    require "argon2"
    account = Account.where(email:).first
    Clog.emit account.nil? ? "Creating account for #{email}" : "Account #{account} already exists"
    account ||= Account.create(email:, status_id: 2)
    hash = Argon2::Password.new({t_cost: 1, m_cost: 5, secret: Config.clover_session_secret}).create(password)
    Clog.emit "Creating password hash for account #{account.id}"
    DB[:account_password_hashes].insert_conflict(
      target: :id,
      update: {password_hash: hash},
    ).insert(id: account.id, password_hash: hash)

    project = Project[project_uuid]
    Clog.emit(project.nil? ? "Creating project #{project_name} with id #{project_uuid}" : "Project #{project} already exists")
    project ||= account.create_project_with_default_policy(project_name, project_id: project_uuid)
    Clog.emit "Setting project #{project} ff=private_locations"
    project.set_ff_private_locations true
    Clog.emit "Setting project #{project} ff=postgres_instance_type_fallback"
    project.set_ff_postgres_instance_type_fallback true
    Clog.emit "Updating project to be billable"
    project.update(billable: true)
    Clog.emit "Creating api key for project #{project}"
    api_key = ApiKey.where(owner_id: account.id, project:, used_for: "api", project_id: project.id).first
    Clog.emit "Api key for project #{project} already exists" if api_key
    api_key ||= ApiKey.create_personal_access_token(account, project:)
    Clog.emit "Unrestricting api key for project #{project}"
    api_key.unrestrict_token_for_project(project.id)
    {
      account_id: account.id,
      api_key: api_key.id,
      project_id: project.id,
      # token: "pat-#{api_key.ubid}-#{api_key.key}"
      token: "[REDACTED]",
    }
  end

  READ_ONLY_ACTIONS = %w[Postgres:view Project:view].freeze

  def self.setup_bot_account(email, password, project_id)
    Clog.emit "Setting up bot account #{email}"
    require "argon2"
    account = Account.where(email:).first
    Clog.emit account.nil? ? "Creating bot account #{email}" : "Bot account #{email} already exists"
    account ||= Account.create(email:, status_id: 2)
    hash = Argon2::Password.new({t_cost: 1, m_cost: 5, secret: Config.clover_session_secret}).create(password)
    DB[:account_password_hashes].insert_conflict(
      target: :id,
      update: {password_hash: hash},
    ).insert(id: account.id, password_hash: hash)

    project = Project[project_id]
    fail "Project #{project_id} not found for bot account" unless project

    unless account.projects_dataset.where(project_id: project.id).count > 0
      Clog.emit "Adding project #{project} to bot account #{account}"
      account.add_project project
    end
    Clog.emit "Setting default project for bot account #{account} to #{project}"
    account.default_project = project
    account.save_changes

    api_key = ApiKey.where(owner_id: account.id, project:, used_for: "api", project_id: project.id).first
    Clog.emit "Bot PAT for #{email} already exists" if api_key
    api_key ||= ApiKey.create_personal_access_token(account, project:)

    Clog.emit "Granting read-only access for bot PAT #{email}"
    READ_ONLY_ACTIONS.each do |action_name|
      action_id = ActionType::NAME_MAP[action_name]
      [account.id, api_key.id].each do |subject_id|
        existing = AccessControlEntry.where(project_id: project.id, subject_id:, action_id:).first
        next if existing
        AccessControlEntry.create(project_id: project.id, subject_id:, action_id:)
      end
    end
    {
      account_id: account.id,
      api_key: api_key.id,
      project_id: project.id,
      token: "[REDACTED]",
    }
  end

  def self.add_location(location)
    provider = location.provider || "aws"
    # nil (not "") so PostgresResource#hostname_suffix's compact drops it instead of
    # producing a leading-dot hostname.
    dns_suffix = location.dns_suffix.to_s.empty? ? nil : location.dns_suffix
    DB.transaction do
      Clog.emit "Checking if location #{location.account_name}:#{location.region} already exists"
      created_location = Location.where(name: location.region, ui_name: location.account_name).first
      if created_location
        Clog.emit "Location #{location.account_name}:#{location.region} already exists, not creating, will update dns_suffix #{dns_suffix} and #{provider} location_credentials"
        created_location.update(dns_suffix:)
        location_credential = upsert_location_credential(created_location.id, location, provider)
      else
        Clog.emit "Creating #{provider} location #{location.account_name}:#{location.region}"
        created_location = Location.create(
          display_name: location.name,
          name: location.region,
          ui_name: location.account_name,
          visible: true,
          provider:,
          dns_suffix:,
        )
        Clog.emit "Creating credentials for location #{location.region}"
        location_credential = create_location_credential(created_location.id, location, provider)
      end

      if (dest = location.otel_otlp_destination)
        Clog.emit "Upserting OtelOtlpDestination for location #{location.account_name}:#{location.region}"
        attrs = {
          otlp_data_endpoint: dest.otlp_data_endpoint,
          otlp_arrow_endpoint: dest.otlp_arrow_endpoint,
          logs_endpoint: dest.logs_endpoint,
          metrics_endpoint: dest.metrics_endpoint,
          auth_audience: dest.auth_audience,
        }
        if (existing = OtelOtlpDestination[created_location.id])
          existing.update(**attrs)
        else
          OtelOtlpDestination.create(**attrs) { it.id = created_location.id }
        end
      end

      return {
        location:,
        location_credential:,
      }
    end
  end

  # Create the provider-appropriate credential for a brand-new location.
  def self.create_location_credential(location_id, location, provider)
    if provider == "gcp"
      # Service-account impersonation: no stored JSON key (credentials_json nil).
      LocationCredentialGcp.create_with_id(
        location_id,
        project_id: location.gcp_project_id,
        service_account_email: location.service_account_email,
        credentials_json: nil,
      )
    else
      LocationCredentialAws.create_with_id(
        location_id,
        access_key: nil,
        secret_key: nil,
        assume_role: location.role,
      )
    end
  end

  # Update an existing credential in place, or create one if the location predates it.
  def self.upsert_location_credential(location_id, location, provider)
    if provider == "gcp"
      if LocationCredentialGcp.where(id: location_id).any?
        LocationCredentialGcp.where(id: location_id).update(project_id: location.gcp_project_id, service_account_email: location.service_account_email)
      else
        Clog.emit "Creating gcp credentials for existing location #{location_id}"
        create_location_credential(location_id, location, provider)
      end
    elsif LocationCredentialAws.where(id: location_id).any?
      LocationCredentialAws.where(id: location_id).update(assume_role: location.role)
    else
      Clog.emit "Creating aws credentials for existing location #{location_id}"
      create_location_credential(location_id, location, provider)
    end
  end

  # Names of gcp locations the config marks project_visible (default true when unset).
  # These populate the project's visible_postgres_locations ff, which gates gcp locations
  # in the Postgres UI (AWS locations are always visible and unaffected).
  def self.visible_gcp_location_names(locations)
    locations.select { |l| l.provider == "gcp" && (l.project_visible.nil? || l.project_visible) }.map(&:region)
  end

  # Idempotent: adds a Prog::LocationNexus strand for the given location if
  # missing. Runs on every deploy so SQL-seeded AWS/GCP locations (which
  # bypass Prog::LocationNexus.assemble) get the strand they need for the
  # daily provider-IP-range refresh.
  def self.ensure_location_nexus_strand(region, ui_name)
    loc = Location.where(name: region, ui_name:).first
    return if loc.nil?
    return unless loc.aws? || loc.gcp?
    return if Strand[loc.id]
    Clog.emit "Creating LocationNexus strand for #{ui_name}:#{region}"
    Strand.create_with_id(loc, prog: "LocationNexus", label: "wait")
  end

  # Create-or-update the capacity-reservation strand when enabled, or pause it (keeping
  # its ODCRs in place) when disabled. A location removed from the config is not visited.
  def self.setup_capacity_reservation(location)
    return if location.provider == "gcp" # ODCRs are an AWS-only concept
    cr = location.capacity_reservation
    created_location = Location.where(name: location.region, ui_name: location.account_name).first

    if cr&.enabled
      Clog.emit "Setting up capacity reservation for location #{location.account_name}:#{location.region}"
      strand = Prog::CapacityReservation.setup(
        location_id: created_location.id,
        instance_families: cr.instance_families || {},
        additional_capacity: cr.additional_capacity,
        enable_all_families: cr.enable_all_families || false,
        allowed_capacity_decrease: cr.allowed_capacity_decrease,
        reconcile_interval: cr.reconcile_interval || Prog::CapacityReservation::RECONCILE_INTERVAL_SECONDS,
        remove_orphaned_reservations: cr.remove_orphaned_reservations || false,
        min_available_az_insufficient_action: cr.min_available_az_insufficient_action || "PAGE",
        wait: true,
      )
      strand.load.decr_pause # resume if a prior disable paused it
    elsif (existing = Prog::CapacityReservation.live_strand(created_location.id))
      Clog.emit "Capacity reservation disabled for #{location.account_name}:#{location.region}; pausing strand #{existing.ubid}, leaving its ODCRs in place"
      s = existing.load
      s.incr_pause unless s.pause_set?
    end
  end

  def self.update_pg_amis(region, version, archs)
    # We just need to find and update the amis
    pg_version = version.delete_prefix "pg"
    DB.transaction do
      DB.run "SET LOCAL clickgres.bypass_dml_blocker__pg_aws_ami = 'true'"
      {arch_arm64: "arm64", arch_x64: "x64"}.each do |arch_attr, arch|
        DB[:pg_aws_ami].insert_conflict(
          target: [:aws_location_name, :pg_version, :arch],
          update: {aws_ami_id: archs[arch_attr]},
        ).insert(
          id: SecureRandom.uuid,
          aws_location_name: region,
          pg_version:,
          arch:,
          aws_ami_id: archs[arch_attr],
        )
      end
    end
  end

  # Upsert a GCE image (the GCP analogue of pg_aws_ami) used to provision Postgres
  # VMs on GCP. Keyed by (arch, gce_image_name); re-running updates pg_versions in
  # place. id is omitted so the pg_gce_image gen_random_ubid_uuid default applies.
  def self.update_pg_gce_image(image)
    pg_versions = Sequel.pg_array(Array(image.pg_versions).map(&:to_s), :text)
    DB.transaction do
      DB.run "SET LOCAL clickgres.bypass_dml_blocker__pg_gce_image = 'true'"
      DB[:pg_gce_image].insert_conflict(
        target: [:arch, :gce_image_name],
        update: {pg_versions:},
      ).insert(
        gce_image_name: image.gce_image_name,
        arch: image.arch,
        pg_versions:,
      )
    end
  end

  def self.ensure_dns_zone_strand(dns_zone)
    DB.transaction do
      if !(dns_strand = Strand[dns_zone.id])
        Clog.emit "Creating DnsZoneNexus strand for zone #{dns_zone.name}"
        Strand.create_with_id(dns_zone.id, prog: "DnsZone::DnsZoneNexus", label: "wait")
      else
        Clog.emit "DnsZoneNexus strand for zone #{dns_zone.name} already exists #{dns_strand}"
      end
    end
  end

  def self.setup_oidc_provider(target_uuid, config)
    Clog.emit "Setting up OIDC provider '#{config.display_name}' with target UUID #{target_uuid}"

    DB.transaction do
      # Check if provider with this UUID already exists and delete it for update
      if (existing = OidcProvider[target_uuid])
        Clog.emit "OIDC provider '#{config.display_name}' (#{target_uuid}) already exists, deleting for update"
        existing.destroy
      end

      # Register the OIDC provider (creates with random ID)
      Clog.emit "Registering OIDC provider '#{config.display_name}' at #{config.url}"
      oidc_provider = OidcProvider.register(
        config.display_name,
        config.url,
        client_id: config.client_id,
        client_secret: config.client_secret,
      )

      # Update the ID to match the target UUID
      old_id = oidc_provider.pk
      Clog.emit "Updating OIDC provider '#{config.display_name}' ID from #{old_id} to #{target_uuid}"
      OidcProvider.dataset.where(id: old_id).update(id: target_uuid)

      # Return the updated provider
      oidc_provider = OidcProvider[target_uuid]
      Clog.emit "OIDC provider '#{config.display_name}' (#{target_uuid}) created successfully"
      oidc_provider
    end
  end

  def self.setup_dns_for_location(project_id, location, vm_size:, boot_image:)
    if location.dns_suffix.nil? || location.dns_suffix.empty?
      Clog.emit "Location #{location.account_name}:#{location.region} has no dns_suffix, not creating dns server"
      fail "Location #{location.account_name}:#{location.region} has no dns_suffix"
    end
    Config.postgres_service_hostname.nil? || Config.postgres_service_hostname.empty? and fail "Config.postgres_service_hostname is not set"
    dns_hostname = "#{location.dns_suffix}.#{Config.postgres_service_hostname}"
    Clog.emit "Setting up DNS Zones for location #{location.account_name}:#{location.region} with dns_hostname #{dns_hostname}"
    DB.transaction do
      dns_server = DnsServer.where(name: dns_hostname).first
      dns_server ||= DnsServer.create(name: dns_hostname)
      dns_zone = DnsZone.where(name: dns_hostname, project_id:).first
      dns_zone ||= DnsZone.create(name: dns_hostname, project_id:)
      unless dns_server.dns_zones.include? dns_zone
        Clog.emit "Adding dns server #{dns_server} to dns zone #{dns_zone}"
        dns_zone.add_dns_server dns_server
      end
      ensure_dns_zone_strand(dns_zone)
      ex_location = Location.where(name: location.region, ui_name: location.account_name).first

      # Provision DNS server VMs
      target_vm_count = 2

      # Count existing VMs (force evaluation to integer)
      existing_vm_count = Integer(dns_server.vms.count)

      # Count running SetupDnsServerVm strands for this DNS server (force evaluation to integer)
      running_strands = Integer(
        Strand.where(prog: "DnsZone::SetupDnsServerVm")
              .where(Sequel.pg_jsonb_op(:stack).contains([{dns_server_id: dns_server.id}]))
              .where(exitval: nil)
              .count,
      )

      vms_to_provision = target_vm_count - existing_vm_count - running_strands
      Clog.emit "Provisioning #{vms_to_provision} (already #{existing_vm_count} existing, #{running_strands} setting up) DNS server VMs for #{dns_server.name}"
      if vms_to_provision > 0
        Clog.emit "Provisioning #{vms_to_provision} DNS server VMs for #{dns_server.name}"
        vms_to_provision.times do
          Prog::DnsZone::SetupDnsServerVm.assemble(
            dns_server,
            vm_size:,
            location_id: ex_location.id,
            boot_image:,
            restrict_ssh_to_control_plane: true,
          )
        end
      else
        Clog.emit "DNS server #{dns_server.name} already has #{existing_vm_count} VMs and #{running_strands} provisioning, target is #{target_vm_count}"
      end
    end
  end

  # class SetupConfig
  #   attr_reader :cleanup_default_locations, :email, :password, :project_name, :locations
  # end

  # `provider` defaults to "aws" when absent (see run_ch_ubi parsing). AWS locations use
  # `role` (assume-role). GCP locations use `gcp_project_id` + `service_account_email`
  # (service-account impersonation; no stored key). `project_visible` (default true) gates
  # a gcp location in the project's visible_postgres_locations ff (the gcp UI gate).
  LocationConfig = Struct.new(:account_name, :name, :region, :role, :dns_suffix, :otel_otlp_destination, :capacity_reservation, :provider, :gcp_project_id, :service_account_email, :project_visible)
  OtelOtlpDestinationConfig = Struct.new(:otlp_data_endpoint, :otlp_arrow_endpoint, :logs_endpoint, :metrics_endpoint, :auth_audience)
  # Standing AWS capacity reservation (ODCR) config for a location. `enabled` defaults to
  # false, so a location only gets a Prog::CapacityReservation strand when opted in.
  CapacityReservationConfig = Struct.new(:enabled, :instance_families, :additional_capacity, :enable_all_families, :allowed_capacity_decrease, :reconcile_interval, :remove_orphaned_reservations, :min_available_az_insufficient_action)
  # pg_amis will look like
  # pg_amis:
  #   us-east-2:
  #     pg18:
  #       arch_x64: ami-ixxxx
  #       arch_arm64: ami-iyyyy
  #     pg17:
  #       arch_x64: ami-ixxxx
  #       arch_arm64: ami-iyyyy
  #     pg16:
  #       arch_x64: ami-ixxxx
  #       arch_arm64: ami-iyyyy
  #   us-west-2:
  #     pg18:
  #       arch_x64: ami-ixxxx
  #       arch_arm64: ami-iyyyy
  #     pg17:
  #       arch_x64: ami-ixxxx
  #       arch_arm64: ami-iyyyy
  #     pg16:
  #       arch_x64: ami-ixxxx
  #       arch_arm64: ami-iyyyy

  PgAmiArchConfig = Struct.new(:arch_x64, :arch_arm64)
  # A GCE image for Postgres on GCP: one row per (arch, gce_image_name), carrying the list
  # of pg major versions the image supports. The GCP analogue of pg_amis (no region: GCE
  # images are global, and one image typically backs multiple versions).
  PgGceImageConfig = Struct.new(:gce_image_name, :arch, :pg_versions)
  DnsAmiArchConfig = Struct.new(:arch_x64, :arch_arm64)
  BotAccountConfig = Struct.new(:email, :password)
  OidcProviderConfig = Struct.new(:display_name, :url, :client_id, :client_secret)

  SetupConfig = Struct.new(:enabled, :cleanup_default_locations, :email, :password, :project_name, :project_uuid, :locations, :pg_amis, :pg_gce_images, :dns_server_amis, :bot_accounts, :oidc_providers)

  def self.run_ch_ubi
    ubicloud_setup_yaml_path = ENV["UBICLOUD_SETUP_YAML_PATH"]
    Clog.emit "UBICLOUD_SETUP_YAML_PATH: #{ubicloud_setup_yaml_path}"
    if ubicloud_setup_yaml_path.nil? || ubicloud_setup_yaml_path.empty?
      err = "UBICLOUD_SETUP_YAML_PATH environment variable is not set"
      Clog.emit "UBICLOUD_SETUP_YAML_PATH environment variable is not set"
      raise err
    end

    setup_yaml = YAML.safe_load_file(ubicloud_setup_yaml_path, permitted_classes: [], aliases: false).transform_keys(&:to_sym)
    setup_yaml[:locations] = setup_yaml[:locations].map do |loc|
      loc = loc.transform_keys(&:to_sym)
      loc[:provider] ||= "aws"
      if (dest = loc[:otel_otlp_destination])
        loc[:otel_otlp_destination] = OtelOtlpDestinationConfig.new(**dest.transform_keys(&:to_sym).slice(*OtelOtlpDestinationConfig.members))
      end
      if (cr = loc[:capacity_reservation])
        # Only the top-level keys become struct fields; instance_families keeps its raw
        # string keys (family => constraint), which is what Prog::CapacityReservation wants.
        loc[:capacity_reservation] = CapacityReservationConfig.new(**cr.transform_keys(&:to_sym).slice(*CapacityReservationConfig.members))
      end
      LocationConfig.new(**loc.slice(*LocationConfig.members))
    end

    # if not setup_yaml[:pg_amis].nil?
    #   setup_yaml[:pg_amis]
    # else
    setup_yaml[:pg_amis] = if setup_yaml[:pg_amis]
      setup_yaml[:pg_amis].transform_values do |versions|
        versions.transform_values do |archs|
          PgAmiArchConfig.new(**archs.transform_keys(&:to_sym).slice(*PgAmiArchConfig.members))
        end
      end
    else
      {}
    end

    setup_yaml[:pg_gce_images] = if setup_yaml[:pg_gce_images]
      setup_yaml[:pg_gce_images].map do |img|
        PgGceImageConfig.new(**img.transform_keys(&:to_sym).slice(*PgGceImageConfig.members))
      end
    else
      []
    end

    # Parse dns_server_amis
    setup_yaml[:dns_server_amis] = if setup_yaml[:dns_server_amis]
      setup_yaml[:dns_server_amis].transform_values do |archs|
        DnsAmiArchConfig.new(**archs.transform_keys(&:to_sym).slice(*DnsAmiArchConfig.members))
      end
    else
      {}
    end

    setup_yaml[:bot_accounts] = if setup_yaml[:bot_accounts]
      setup_yaml[:bot_accounts].transform_values { |ba| BotAccountConfig.new(**ba.transform_keys(&:to_sym).slice(*BotAccountConfig.members)) }
    else
      {}
    end

    setup_yaml[:oidc_providers] = if setup_yaml[:oidc_providers]
      setup_yaml[:oidc_providers].transform_values { |oidc| OidcProviderConfig.new(**oidc.transform_keys(&:to_sym).slice(*OidcProviderConfig.members)) }
    else
      {}
    end

    setup_config = SetupConfig.new(**setup_yaml.slice(*SetupConfig.members))

    (return Clog.emit "Setup is disabled, exiting") unless setup_config.enabled

    base_setup = setup_ubicloud(setup_config.email, setup_config.password, setup_config.project_name, setup_config.project_uuid)
    Clog.emit base_setup

    project_id = base_setup[:project_id]

    setup_config.bot_accounts.each do |name, bot|
      Clog.emit "Setting up bot account: #{name}"
      bot_setup = setup_bot_account(bot.email, bot.password, project_id)
      Clog.emit bot_setup
    end

    setup_config.oidc_providers.each do |uuid, oidc_config|
      Clog.emit "Setting up OIDC provider: #{uuid}"
      oidc_provider = setup_oidc_provider(uuid, oidc_config)
      Clog.emit "OIDC provider #{uuid} setup complete: #{oidc_provider.display_name}"
    end

    if setup_config.cleanup_default_locations
      hide_default_locations
    end

    setup_config.locations.each do |location|
      add_location(location)
      ensure_location_nexus_strand(location.region, location.account_name)
      setup_capacity_reservation(location)
      vm_size, boot_image = if location.provider == "gcp"
        ["c4a-standard-4", "ubuntu-noble"]
      else
        # Get DNS AMI for this region (x64 arch required)
        dns_ami = setup_config.dns_server_amis.dig(location.region, :arch_x64)
        fail "DNS AMI not configured for region #{location.region}" if dns_ami.nil? || dns_ami.empty?
        ["m7i.large", dns_ami]
      end
      setup_dns_for_location(project_id, location, vm_size:, boot_image:)
    end

    setup_config.pg_amis.each do |region, versions|
      versions.each do |version, archs|
        Clog.emit "Updating pg_amis for region #{region}, version #{version}, archs #{archs}"
        update_pg_amis(region, version, archs)
      end
    end

    setup_config.pg_gce_images.each do |image|
      Clog.emit "Updating pg_gce_image #{image.gce_image_name} (#{image.arch}) for pg_versions #{image.pg_versions}"
      update_pg_gce_image(image)
    end

    aws_family_options = %w[c6gd m6id m6gd i8ge i7i i7ie r8gd r6gd r6id m7gd r7gd r8id m8id]

    Clog.emit "Enabling AWS instance types: #{aws_family_options}"
    project = Project[project_id]
    aws_family_options.each do |family|
      project.send(:"set_ff_enable_#{family}", true)
    end

    Clog.emit "Enabling Postgres Standbys to always use different AZs for standbys [postgres_aws_use_different_azs_for_standbys]"
    project.send(:set_ff_postgres_aws_use_different_azs_for_standbys, true)

    Clog.emit "Enabling AWS Postgres management SSH over IPv6 [postgres_aws_ssh_ipv6]"
    project.set_ff_postgres_aws_ssh_ipv6(true)

    Clog.emit "Enabling weekly Postgres maintenance window days [postgres_enable_maintenance_window_days]"
    project.set_ff_postgres_enable_maintenance_window_days(true)

    Clog.emit "Restricting Postgres maintenance windows to platform-only events [postgres_maintenance_window_platform_only]"
    project.set_ff_postgres_maintenance_window_platform_only(true)

    # Enable per-subnet (dedicated) GCP VPCs by default for the project, so each GCP
    # resource gets its own VPC instead of a shared per-location VPC. Column, not a ff.
    Clog.emit "Enabling GCP dedicated subnet VPCs [gcp_dedicated_subnet_vpcs]"
    project.update(gcp_dedicated_subnet_vpcs: true)

    # GCP postgres locations are gated in the UI by the visible_postgres_locations ff.
    # When the config declares any gcp locations, setup owns this list: it's set to exactly
    # the project_visible gcp names (others are hidden). AWS-only configs leave it untouched.
    if setup_config.locations.any? { |l| l.provider == "gcp" }
      visible = visible_gcp_location_names(setup_config.locations)
      Clog.emit "Setting visible_postgres_locations for gcp UI visibility: #{visible}"
      project.set_ff_visible_postgres_locations(visible)
    end
  end
end

# :nocov:
UbicloudSetup.run_ch_ubi if __FILE__ == $0
# :nocov:
