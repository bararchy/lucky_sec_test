{% skip_file unless flag?(:with_sec_tests) %}

require "../spec_helper"

describe "SecTester" do
  # Testing the auth page with SQLi attack
  it "Testing sign_in page for SQLi, OSI, XSS attacks" do
    with_cleanup(scanner) do
      target = scanner.build_target(SignIns::Create) do |t|
        t.body = "user%3Aemail=test%40test.com&user%3Apassword=1234"
      end
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: [
          "sqli",
          "osi",
          "xss",
        ],
        target: target
      )
    end
  end

  # Testing the auth page with Dom XSS attack
  it "Testing sign_in for dom based XSS" do
    with_cleanup(scanner) do
      target = scanner.build_target(SignIns::New)
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "dom_xss",
        target: target
      )
    end
  end

  # Testing the auth page with Headers Security attack
  it "testing root for header security issues" do
    with_cleanup(scanner) do
      target = scanner.build_target
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "header_security",
        target: target,
        severity_threshold: :medium
      )
    end
  end

  # Testing the auth page with Cookies Security attack
  it "testing root for cookie security issues" do
    with_cleanup(scanner) do
      target = scanner.build_target
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "cookie_security",
        target: target,
        severity_threshold: :medium
      )
    end
  end

  # Testing JS file for 3rd party issues
  it "Tests /js/app.js for 3rd party issues" do
    with_cleanup(scanner) do
      # TODO: Need `scanner.build_target` to take a String
      # or something to be able to test things like this.
      # Or... maybe this is your escape hatch?
      target = SecTester::Target.new(Lucky::AssetHelpers.asset("js/app.js"))
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: "retire_js",
        target: target
      )
    end
  end

  it "tests API actions" do
    with_cleanup(scanner) do
      api_headers = HTTP::Headers{"Content-Type" => "application/json", "Accept" => "application/json"}
      target = scanner.build_target(Api::SignIns::Create, headers: api_headers) do |t|
        t.body = {"user" => {"email" => "aa%40aa.com", "password" => "123456789"}}.to_json
      end
      scanner.run_check(
        scan_name: "ref: #{ENV["GITHUB_REF"]?} commit: #{ENV["GITHUB_SHA"]?} run id: #{ENV["GITHUB_RUN_ID"]?}",
        tests: [
          "sqli",                 # Testing for SQL Injection issues (https://docs.neuralegion.com/docs/sql-injection)
          "jwt",                  # Testing JWT usage (https://docs.neuralegion.com/docs/broken-jwt-authentication)
          "xss",                  # Checking for Cross Site Scripting attacks (https://docs.neuralegion.com/docs/reflective-cross-site-scripting-rxss)
          "ssrf",                 # Checking for SSRF (https://docs.neuralegion.com/docs/server-side-request-forgery-ssrf)
          "proto_pollution",      # Checking for proto pollution based vulnerabilities (https://docs.neuralegion.com/docs/prototype-pollution)
          "full_path_disclosure", # Checking for full path disclourse on api error (https://docs.neuralegion.com/docs/full-path-disclosure)
        ],
        target: target,
        severity_threshold: :medium
      )
    end
  end
end

private def scanner
  LuckySecTester.new
end

private def with_cleanup(tester : LuckySecTester)
  yield
ensure
  tester.try &.cleanup
end
