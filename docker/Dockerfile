ARG SSP_VERSION="v2.5.0"
FROM cirrusid/simplesamlphp:${SSP_VERSION}
#FROM cicnavi/simplesamlphp:${SSP_VERSION}

# --build-arg OIDANCHOR_VERSION
ARG OIDANCHOR_VERSION="@dev"

ENV STAGINGCOMPOSERREPOS=oidanchor \
    COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidanchor:$OIDANCHOR_VERSION"
ADD . /var/simplesamlphp/staging-modules/oidanchor

RUN /opt/simplesaml/staging-install.sh
RUN /opt/simplesaml/module-setup.sh
ADD docker/ssp/module_oidanchor.php /var/simplesamlphp/config/module_oidanchor.php
ADD docker/ssp/authsources.php /var/simplesamlphp/config/authsources.php
ADD docker/ssp/config-override.php /var/simplesamlphp/config/config-override.php
ADD docker/ssp/oidanchor_module.crt /var/simplesamlphp/cert/oidanchor_module.crt
ADD docker/ssp/oidanchor_module.key /var/simplesamlphp/cert/oidanchor_module.key
ADD docker/apache-override.cf /etc/apache2/sites-enabled/ssp-override.cf

RUN chown www-data /var/simplesamlphp/cert/oidanchor* \
    && chmod 660 /var/simplesamlphp/cert/oidanchor*
