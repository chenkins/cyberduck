/*
 * DRACOON API
 * REST Web Services for DRACOON<br><br>This page provides an overview of all available and documented DRACOON APIs, which are grouped by tags.<br>Each tag provides a collection of APIs that are intended for a specific area of the DRACOON.<br><br><a title='Developer Information' href='https://developer.dracoon.com'>Developer Information</a>&emsp;&emsp;<a title='Get SDKs on GitHub' href='https://github.com/dracoon'>Get SDKs on GitHub</a><br><br><a title='Terms of service' href='https://www.dracoon.com/terms/general-terms-and-conditions/'>Terms of service</a>
 *
 * OpenAPI spec version: 4.30.0-beta.4
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */

package ch.cyberduck.core.sds.io.swagger.client.model;

import java.util.Objects;
import java.util.Arrays;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.v3.oas.annotations.media.Schema;
/**
 * Infrastructure properties
 */
@Schema(description = "Infrastructure properties")
@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-08-16T11:28:10.116221+02:00[Europe/Zurich]")
public class InfrastructureProperties {
  @JsonProperty("smsConfigEnabled")
  private Boolean smsConfigEnabled = null;

  @JsonProperty("mediaServerConfigEnabled")
  private Boolean mediaServerConfigEnabled = null;

  @JsonProperty("s3DefaultRegion")
  private String s3DefaultRegion = null;

  @JsonProperty("s3EnforceDirectUpload")
  private Boolean s3EnforceDirectUpload = null;

  @JsonProperty("isDracoonCloud")
  private Boolean isDracoonCloud = null;

  @JsonProperty("tenantUuid")
  private String tenantUuid = null;

  public InfrastructureProperties smsConfigEnabled(Boolean smsConfigEnabled) {
    this.smsConfigEnabled = smsConfigEnabled;
    return this;
  }

   /**
   * Allow sending of share passwords via SMS
   * @return smsConfigEnabled
  **/
  @Schema(description = "Allow sending of share passwords via SMS")
  public Boolean isSmsConfigEnabled() {
    return smsConfigEnabled;
  }

  public void setSmsConfigEnabled(Boolean smsConfigEnabled) {
    this.smsConfigEnabled = smsConfigEnabled;
  }

  public InfrastructureProperties mediaServerConfigEnabled(Boolean mediaServerConfigEnabled) {
    this.mediaServerConfigEnabled = mediaServerConfigEnabled;
    return this;
  }

   /**
   * Determines if the media server is enabled
   * @return mediaServerConfigEnabled
  **/
  @Schema(description = "Determines if the media server is enabled")
  public Boolean isMediaServerConfigEnabled() {
    return mediaServerConfigEnabled;
  }

  public void setMediaServerConfigEnabled(Boolean mediaServerConfigEnabled) {
    this.mediaServerConfigEnabled = mediaServerConfigEnabled;
  }

  public InfrastructureProperties s3DefaultRegion(String s3DefaultRegion) {
    this.s3DefaultRegion = s3DefaultRegion;
    return this;
  }

   /**
   * Suggested S3 Region
   * @return s3DefaultRegion
  **/
  @Schema(description = "Suggested S3 Region")
  public String getS3DefaultRegion() {
    return s3DefaultRegion;
  }

  public void setS3DefaultRegion(String s3DefaultRegion) {
    this.s3DefaultRegion = s3DefaultRegion;
  }

  public InfrastructureProperties s3EnforceDirectUpload(Boolean s3EnforceDirectUpload) {
    this.s3EnforceDirectUpload = s3EnforceDirectUpload;
    return this;
  }

   /**
   * &amp;#128640; Since v4.15.0  Enforce direct upload to S3
   * @return s3EnforceDirectUpload
  **/
  @Schema(description = "&#128640; Since v4.15.0  Enforce direct upload to S3")
  public Boolean isS3EnforceDirectUpload() {
    return s3EnforceDirectUpload;
  }

  public void setS3EnforceDirectUpload(Boolean s3EnforceDirectUpload) {
    this.s3EnforceDirectUpload = s3EnforceDirectUpload;
  }

  public InfrastructureProperties isDracoonCloud(Boolean isDracoonCloud) {
    this.isDracoonCloud = isDracoonCloud;
    return this;
  }

   /**
   * &amp;#128640; Since v4.21.0  Determines if the DRACOON Core is deployed in the cloud environment
   * @return isDracoonCloud
  **/
  @Schema(description = "&#128640; Since v4.21.0  Determines if the DRACOON Core is deployed in the cloud environment")
  public Boolean isIsDracoonCloud() {
    return isDracoonCloud;
  }

  public void setIsDracoonCloud(Boolean isDracoonCloud) {
    this.isDracoonCloud = isDracoonCloud;
  }

  public InfrastructureProperties tenantUuid(String tenantUuid) {
    this.tenantUuid = tenantUuid;
    return this;
  }

   /**
   * &amp;#128640; Since v4.21.0  Current tenant UUID
   * @return tenantUuid
  **/
  @Schema(description = "&#128640; Since v4.21.0  Current tenant UUID")
  public String getTenantUuid() {
    return tenantUuid;
  }

  public void setTenantUuid(String tenantUuid) {
    this.tenantUuid = tenantUuid;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    InfrastructureProperties infrastructureProperties = (InfrastructureProperties) o;
    return Objects.equals(this.smsConfigEnabled, infrastructureProperties.smsConfigEnabled) &&
        Objects.equals(this.mediaServerConfigEnabled, infrastructureProperties.mediaServerConfigEnabled) &&
        Objects.equals(this.s3DefaultRegion, infrastructureProperties.s3DefaultRegion) &&
        Objects.equals(this.s3EnforceDirectUpload, infrastructureProperties.s3EnforceDirectUpload) &&
        Objects.equals(this.isDracoonCloud, infrastructureProperties.isDracoonCloud) &&
        Objects.equals(this.tenantUuid, infrastructureProperties.tenantUuid);
  }

  @Override
  public int hashCode() {
    return Objects.hash(smsConfigEnabled, mediaServerConfigEnabled, s3DefaultRegion, s3EnforceDirectUpload, isDracoonCloud, tenantUuid);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class InfrastructureProperties {\n");
    
    sb.append("    smsConfigEnabled: ").append(toIndentedString(smsConfigEnabled)).append("\n");
    sb.append("    mediaServerConfigEnabled: ").append(toIndentedString(mediaServerConfigEnabled)).append("\n");
    sb.append("    s3DefaultRegion: ").append(toIndentedString(s3DefaultRegion)).append("\n");
    sb.append("    s3EnforceDirectUpload: ").append(toIndentedString(s3EnforceDirectUpload)).append("\n");
    sb.append("    isDracoonCloud: ").append(toIndentedString(isDracoonCloud)).append("\n");
    sb.append("    tenantUuid: ").append(toIndentedString(tenantUuid)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}
