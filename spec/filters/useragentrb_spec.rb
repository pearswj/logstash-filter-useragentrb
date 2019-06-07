# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/useragentrb"

describe LogStash::Filters::UserAgentRuby do

  describe "defaults" do
    config <<-CONFIG
      filter {
        useragentrb {
          source => "message"
          target => "ua"
        }
      }
    CONFIG

    sample "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "Chrome"
      insist { subject.get("[ua][os][full]") } == "Linux"
      insist { subject.get("[ua][major]") } == "26"
      insist { subject.get("[ua][minor]") } == "0"
    end

    sample "MacOutlook/16.24.0.190414 (Intelx64 Mac OS X Version 10.14.4 (Build 18E226))" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "MacOutlook"
      insist { subject.get("[ua][major]") } == "16"
      insist { subject.get("[ua][minor]") } == "24"
      insist { subject.get("[ua][os][full]") } == "Mac OS X 10.14.4"
      insist { subject.get("[ua][os][name]") } == "Mac OS X"
      insist { subject.get("[ua][os][version]") } == "10.14.4"
      insist { subject.get("[ua][os][major]") } == "10"
      insist { subject.get("[ua][os][minor]") } == "14"
    end

    sample "Example/1.0.0.0 (Macintosh; Intel Mac OS X 10_14_5) Mozilla/5.0" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "Other"
      insist { subject.get("[ua][os][full]") } == "Mac OS X 10.14.5"
      insist { subject.get("[ua][os][name]") } == "Mac OS X"
      insist { subject.get("[ua][os][major]") } == "10"
      insist { subject.get("[ua][os][minor]") } == "14"
    end

    sample "Example/1.0.0.0 (Windows NT 10.0; Win64; x64) Mozilla/5.0" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "Other"
      insist { subject.get("[ua][os][full]") } == "Windows 10"
      insist { subject.get("[ua][os][name]") } == "Windows"
      insist { subject.get("[ua][os][version]") } == "10"
      insist { subject.get("[ua][os][major]") } == "10"
      insist { subject.get("[ua][os][minor]") } == ""
    end

    sample "Example/1.0.0.0 (Windows NT 6.3; Win64; x64) Mozilla/5.0" do
      insist { subject }.include?("ua")
      insist { subject.get("[ua][name]") } == "Other"
      insist { subject.get("[ua][os][full]") } == "Windows 8.1"
      insist { subject.get("[ua][os][name]") } == "Windows"
      insist { subject.get("[ua][os][version]") } == "8.1"
      insist { subject.get("[ua][os][major]") } == "8.1" # windows version parsing is broken (fixed with new regexes.yaml)
      insist { subject.get("[ua][os][minor]") } == "" # windows version parsing is broken (fixed with new regexes.yaml)
    end
  end

end
