#include <iostream>
#include <string>
#include <pqxx/pqxx>
#include <curl/curl.h>
#include "json.hpp"
#include <thread>

const std::string apiKey = "41c1fe0f-073b-42ec-b2ea-b9e4c5289a30";

// Callback function to write response data from the HTTP request
size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *output)
{
    size_t totalSize = size * nmemb;
    output->append(static_cast<char *>(contents), totalSize);
    return totalSize;
}

int main()
{
	std::cout << "worked" << std::endl;
    // PostgreSQL connection string
    const std::string connStr = "dbname=fleet user=vajra password=admin host=localhost port=5432";

    CURL *curl;
    CURLcode res;

    // Initialize the libcurl library
    curl = curl_easy_init();

    if (curl)
    {
        try
        {
            // Create a PostgreSQL connection
            pqxx::connection conn(connStr);

            // Fetch data from the NVD API
            int startIndex = 0;
            int resultsPerPage = 1000;
            int totalResults = 0;

            pqxx::work txn(conn);
            pqxx::result result = txn.exec("select id from nvd_cves order by id desc limit 1");
            if (result.size() == 1)
            {
                for (pqxx::result::const_iterator i = result.begin(); i != result.end(); ++i)
                {
                    startIndex = i["id"].as<long>();
                    totalResults = i["id"].as<long>();
                }
            }
            txn.commit();

            nlohmann::json criteriaArray;

            while (startIndex <= totalResults)
            {
                // Construct the NVD API URL
                std::string apiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=" + std::to_string(resultsPerPage) + "&startIndex=" + std::to_string(startIndex);

                // Configure the libcurl request
                curl_easy_setopt(curl, CURLOPT_URL, apiUrl.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

                // Add the API key to the request headers
                struct curl_slist *headers = NULL;
                headers = curl_slist_append(headers, ("api_key: " + apiKey).c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                // Response data will be stored in this string
                std::string response_data;

                // Set the callback function to handle response data
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

                // Perform the HTTP request
                res = curl_easy_perform(curl);

                if (res != CURLE_OK)
                {
                    std::cerr << "Error: " << curl_easy_strerror(res) << std::endl;
                }
                else
                {

                    // std::cout << response_data << std::endl;
                    nlohmann::json json_data = nlohmann::json::parse(response_data);
                    std::string cve_id, published, lastModified, vulnStatus, descriptions, metrics, weaknesses, reference, configurations, cpe_string, baseSeverity, versionStartIncluding, versionEndIncluding, versionEndExcluding;
                    long baseScore, exploitabilityScore, impactScore;
                    // Extract the totalResults value for updating the while loop
                    totalResults = json_data["totalResults"];
                    for (const auto &vuln : json_data["vulnerabilities"])
                    {
                        // Extract data from the JSON
                        cve_id = vuln["cve"]["id"];
                        published = vuln["cve"]["published"];
                        lastModified = vuln["cve"]["lastModified"];
                        vulnStatus = vuln["cve"]["vulnStatus"];
                        // Extract and serialize nested JSON fields
                        if (vuln["cve"].find("descriptions") != vuln["cve"].end())
                        {
                            descriptions = vuln["cve"]["descriptions"].dump();
                        }
                        if (vuln["cve"].find("metrics") != vuln["cve"].end())
                        {
                            metrics = vuln["cve"]["metrics"].dump();
                        }
                        if (vuln["cve"].find("weaknesses") != vuln["cve"].end())
                        {
                            weaknesses = vuln["cve"]["weaknesses"].dump();
                        }
                        if (vuln["cve"].find("references") != vuln["cve"].end())
                        {
                            reference = vuln["cve"]["references"].dump();
                        }

                        std::vector<std::string> criteriaKeys;
                        if (vuln["cve"].find("configurations") != vuln["cve"].end())
                        {
                            configurations = vuln["cve"]["configurations"].dump();
                            if (vuln["cve"]["configurations"][0]["nodes"][0].find("cpeMatch") != vuln["cve"]["configurations"][0]["nodes"][0].end())
                            {
                                criteriaArray = vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"];

                                for (const auto &criteria : criteriaArray)
                                {
                                    criteriaKeys.push_back(criteria["criteria"]);
                                }
                                // Serialize the criteria keys into a JSON array
                                cpe_string = nlohmann::json(criteriaKeys).dump();
                                auto &cpeMatch = vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0];

                                if (vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0].find("versionEndIncluding") != vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0].end())
                                {
                                    versionEndIncluding = vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndIncluding"];
                                }
                                if (vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0].find("versionStartIncluding") != vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0].end())
                                {
                                    versionStartIncluding = vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionStartIncluding"];
                                }
                                else
                                {
                                    versionStartIncluding = "0";
                                }
                                if (vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0].find("versionEndExcluding") != vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0].end())
                                {
                                    versionEndExcluding = vuln["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"];
                                }
                            }
                        }
                        if (vuln["cve"]["metrics"].find("cvssMetricV2") != vuln["cve"]["metrics"].end())
                        {
                            if (vuln["cve"]["metrics"]["cvssMetricV2"][0].find("cvssData") != vuln["cve"]["metrics"]["cvssMetricV2"][0].end())
                            {
                                baseScore = vuln["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"];
                            }
                            if (vuln["cve"]["metrics"]["cvssMetricV2"][0].find("baseSeverity") != vuln["cve"]["metrics"]["cvssMetricV2"][0].end())
                            {
                                baseSeverity = vuln["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"];
                            }
                            if (vuln["cve"]["metrics"]["cvssMetricV2"][0].find("exploitabilityScore") != vuln["cve"]["metrics"]["cvssMetricV2"][0].end())
                            {
                                exploitabilityScore = vuln["cve"]["metrics"]["cvssMetricV2"][0]["exploitabilityScore"];
                            }
                            if (vuln["cve"]["metrics"]["cvssMetricV2"][0].find("impactScore") != vuln["cve"]["metrics"]["cvssMetricV2"][0].end())
                            {
                                impactScore = vuln["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"];
                            }
                        }
                        // Insert data into the PostgreSQL table
                        pqxx::work txn(conn);
                        txn.exec(
                            "INSERT INTO nvd_cves(cve_id, published, lastModified, vulnStatus, descriptions, metrics, weaknesses, configurations, reference, cpe_string, baseScore, baseSeverity, exploitabilityScore, impactScore, versionstartincluding, versionendincluding) VALUES (" +
                            txn.quote(cve_id) + ", " + txn.quote(published) + ", " + txn.quote(lastModified) + ", " + txn.quote(vulnStatus) + ", " +
                            txn.quote(descriptions) + ", " + txn.quote(metrics) + ", " + txn.quote(weaknesses) + ", " + txn.quote(configurations) + ", " + txn.quote(reference) + ", " + txn.quote(cpe_string) + ", " + txn.quote(baseScore) + ", " + txn.quote(baseSeverity) + ", " + txn.quote(exploitabilityScore) + ", " + txn.quote(impactScore) + ", " + txn.quote(versionStartIncluding) + ", " + txn.quote(versionEndIncluding) + ");");

                        txn.commit();
                    }

                    // Update the startIndex based on the totalResults
                    startIndex += resultsPerPage;
                }
                // sleep
                std::this_thread::sleep_for(std::chrono::seconds(300));
            }

            // Close the PostgreSQL connection
            conn.disconnect();

            // Cleanup libcurl
            curl_easy_cleanup(curl);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    return 0;
}
