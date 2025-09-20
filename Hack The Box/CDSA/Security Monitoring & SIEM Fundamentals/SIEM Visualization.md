
# Failed Logon Attempts


Dashboards in SIEM solutions serve as containers for multiple visualizations, allowing us to organize and display data in a meaningful way.

In this and the following sections, we will create a dashboard and some visualizations from scratch.

---

## Developing Our First Dashboard & Visualization

Navigate to the bottom of this section and click on `Click here to spawn the target system!`

Now, navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

Delete the existing "SOC-Alerts" dashboard as follows.

![Elastic dashboard interface showing 'SOC-Alerts' with options to delete or create a dashboard.](https://academy.hackthebox.com/storage/modules/211/visualization29.png)

When visiting the Dashboard page again we will be presented with a message indicating that no dashboards currently exist. Additionally, there will be an option available to create a new Dashboard and its first visualization. To initiate the creation of our first dashboard, we simply have to click on the "Create new dashboard" button.

![Elastic interface prompting to create the first dashboard with options to install sample data and create a new dashboard.](https://academy.hackthebox.com/storage/modules/211/dashboard.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

![Elastic interface for editing a new dashboard, prompting to add the first visualization with options to create or add from library.](https://academy.hackthebox.com/storage/modules/211/visualization.png)

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

Before proceeding with any configuration, it is important for us to first click on the calendar icon to open the time picker. Then, we need to specify the date range as "last 15 years". Finally, we can click on the "Apply" button to apply the specified date range to the data.

![Elastic dashboard creation interface with options to add filter, select index pattern 'windows*', search field names, and choose 'Bar vertical stacked' visualization.](https://academy.hackthebox.com/storage/modules/211/visualization1.png)

There are four things for us to notice on this window:

1. A filter option that allows us to filter the data before creating a graph. For example, if our goal is to display failed logon attempts, we can use a filter to only consider event IDs that match `4625 – Failed logon attempt on a Windows system`. The following image demonstrates how we can specify such a filter.
    
    ![Elastic dashboard interface with 'Add filter' option open, setting filter for 'event.code' to '4625' using operator 'is'.](https://academy.hackthebox.com/storage/modules/211/visualization2.png)
    
2. This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
    
3. This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. For example, let's say we are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.
    
    ![Elastic dashboard interface with a filter for 'event.code: 4625' and search for fields starting with 'user.' showing available fields like 'user.name.keyword'.](https://academy.hackthebox.com/storage/modules/211/visualization11.png)
    
    "Why `user.name.keyword` and not `user.name`?", you may ask. We should use the `.keyword` field when it comes to aggregations. Please refer to this [stackoverflow question](https://stackoverflow.com/questions/48869795/difference-between-a-field-and-the-field-keyword) for a more elaborate answer.
    
4. Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.
    
    ![Elastic interface showing visualization type options with 'Bar vertical stacked' selected, including other options like 'Metric' and 'Table'.](https://academy.hackthebox.com/storage/modules/211/visualization4.png)
    

---

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Elastic table configuration interface with options to add or drag-and-drop fields for rows, columns, and metrics.](https://academy.hackthebox.com/storage/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked by count of records in descending order.](https://academy.hackthebox.com/storage/modules/211/visualization6.png)

**Note**: You will notice `Rank by Alphabetical` and not `Rank by Count of records` like in the screenshot above. This is OK. By the time you perform the next configuration below, `Count of records` will become available.

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Elastic table configuration showing 'windows*' index pattern, with 'Top values of user.name.keyword' in rows, and options to add fields to columns and metrics.](https://academy.hackthebox.com/storage/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Elastic metrics configuration interface showing quick functions like Average, Count, and Sum, with 'Count' selected.](https://academy.hackthebox.com/storage/modules/211/visualization8.png)

As soon as we select "Count" as the metric, we will observe that the table gets populated with data (assuming that there are events present in the selected data set)

![Elastic table showing top values of 'user.name.keyword' with counts, and metrics configuration set to 'Count' for records.](https://academy.hackthebox.com/storage/modules/211/visualization9.png)

One final addition to the table is to include another "Rows" setting to show the machine where the failed logon attempt occurred. To do this, we will select the `host.hostname.keyword` field, which represents the computer reporting the failed logon attempt. This will allow us to display the hostname or machine name alongside the count of failed logon attempts, as shown in the image.

![Elastic table showing top values of 'user.name.keyword' and 'host.hostname.keyword' with record counts, configured in rows.](https://academy.hackthebox.com/storage/modules/211/visualization12.png)

Now we can see three columns in the table, which contain the following information:

1. The username of the individuals logging in (Note: It currently displays both users and computers. Ideally, a filter should be implemented to exclude computer devices and only display users).
    
2. The machine on which the logon attempt occurred.
    
3. The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).
    

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard, appearing as shown in the following image.

![Elastic dashboard showing a table with top values of user names and hostnames, and their record counts.](https://academy.hackthebox.com/storage/modules/211/visualization13.png)

Let's not forget to save the dashboard as well. We can do so by simply clicking on the "Save" button.

![Elastic interface showing 'Save dashboard' dialog with title 'SOC-Alerts', description for HTB Academy's SOC Analyst Job-Role Path, and option to store time with dashboard.](https://academy.hackthebox.com/storage/modules/211/visualization15.png)

---

## Refining The Visualization

Suppose the SOC Manager suggested the following refinements:

- Clearer column names should be specified in the visualization
- The Logon Type should be included in the visualization
- The results in the visualization should be sorted
- The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames should not be monitored
- [Computer accounts](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-computer) should not be monitored (not a good practice)

Let's refine the visualization we created, so that it fulfills the suggestions above.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

The dashboard we previously created should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard interface showing a list with 'SOC-Alerts' and options to create or edit a dashboard.](https://academy.hackthebox.com/storage/modules/211/visualization16.png)

Let's now click on the "gear" button at the upper-right corner of our visualization, and then click on "Edit lens".

![Elastic dashboard editing 'SOC-Alerts' with a table of top user and hostnames, and options to edit lens, clone panel, or edit panel title.](https://academy.hackthebox.com/storage/modules/211/visualization18.png)

"Top values of user.name.keyword" should be changed as follows.

![Elastic table configuration with 'Top values of user.name.keyword' and 'host.hostname.keyword' in rows, and 'Count of records' in metrics.](https://academy.hackthebox.com/storage/modules/211/visualization19.png)

![Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked alphabetically in ascending order, with display name 'Username'.](https://academy.hackthebox.com/storage/modules/211/visualization17.png)

"Top values of host.hostname.keyword" should be changed as follows.

![Elastic interface for configuring rows, selecting 'host.hostname.keyword' field, displaying top 1000 values, ranked by count of records in descending order, with display name 'Event logged by'.](https://academy.hackthebox.com/storage/modules/211/visualization20.png)

The "Logon Type" can be added as follows (we will use the `winlog.logon.type.keyword` field).

![Elastic table configuration with 'Top values of user.name.keyword' and 'Event logged by' in rows, and 'Count of records' in metrics, with option to add fields.](https://academy.hackthebox.com/storage/modules/211/visualization21.png) ![Rows configuration panel with 'winlog.logon.type.keyword' field selected, number of values set to 1000, ranked by count of records in descending order, display name 'Logon Type'.](https://academy.hackthebox.com/storage/modules/211/visualization22.png)

"Count of records" should be changed as follows. ![Metrics panel with 'Count' function selected, field set to 'Records', display name '# of logins', text alignment 'Right'.](https://academy.hackthebox.com/storage/modules/211/visualization23.png)

We can introduce result sorting as follows. ![Elastic dashboard showing a table with columns: Username, Event logged by, Logon Type, and '# of logins' sorted descending.](https://academy.hackthebox.com/storage/modules/211/visualization25.png)

All we have to do now is click on "Save and return".

The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames can be excluded by specifying additional filters as follows.

![Elastic dashboard with filter settings: Field 'user.name.keyword', operator 'is not', value 'DESKTOP-DPOESND'.](https://academy.hackthebox.com/storage/modules/211/visualization24.png)

Computer accounts can be excluded by specifying the following KQL query and clicking on the "Update" button.

  SIEM Visualization Example 1: Failed Logon Attempts (All Users)

```shell-session
NOT user.name: *$ AND winlog.channel.keyword: Security
```

The `AND winlog.channel.keyword: Security` part is to ensure that no unrelated logs are accounted for.

![Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'.](https://academy.hackthebox.com/storage/modules/211/visualization34.png)

This is our visualization after all the refinements we performed.

![Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, displaying a table with columns: Username, Event logged by, Logon Type, and '# of logins'.](https://academy.hackthebox.com/storage/modules/211/visualization35.png)

Finally, let's give our visualization a title by clicking on "No Title".

![Elastic dashboard with filters applied, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'. Customize panel dialog open with 'Show panel title' option.](https://academy.hackthebox.com/storage/modules/211/visualization36.png)

Don't forget to click on the "Save" button (the one on the upper-right hand side of the window).

# Failed Logon Attempts [Disabled Users]

In this SIEM visualization example we want to create visualization to monitor failed login attempts against disabled users.

We mention "failed" because it is not possible to log in with a disabled user, so it will never be successful even if the correct credentials are provided. In a scenario where the correct credentials are provided, the Windows logs will contain an additional SubStatus value of 0xC0000072, that indicates the reason of the failure.

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard interface displaying a list of dashboards. The screen shows a single dashboard titled 'SOC-Alerts' with an edit icon highlighted. A 'Create dashboard' button is visible.](https://academy.hackthebox.com/storage/modules/211/visualization16.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

![Elastic dashboard interface with highlighted elements: 'Add filter' button, filter selection ('windows*'), search field for field names, and 'Bar vertical stacked' chart type.](https://academy.hackthebox.com/storage/modules/211/visualization1.png)

There are four things for us to notice on this window:

1. A filter option that allows us to filter the data before creating a graph. In this case our goal is to display failed logon attempts against disabled users only. We can use a filter to only consider event IDs that match `4625 – Failed logon attempt on a Windows system`, like we did in the previous visualization example. In this case though, we should also take into account the SubStatus (`winlog.event_data.SubStatus` field) that indicates, when set to 0xC0000072, that the failure is due to a logon with disabled user. The following image demonstrates how we can specify such a filter.
    
    ![Elastic dashboard with an active filter: 'event.code: 4625' and 'winlog.event_data.SubStatus: 0xc0000072'. Edit filter panel shows 'winlog.event_data.SubStatus' field set to '0xc0000072' (Disabled user) with operator 'is'.](https://academy.hackthebox.com/storage/modules/211/visualization30.png)
    
2. This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
    
3. This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. Like in the previous visualization, we are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.
    
    ![Elastic dashboard search interface showing a query for 'user.' with available fields like related.user.keyword and user.name.keyword.](https://academy.hackthebox.com/storage/modules/211/visualization11.png)
    
4. Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.
    
    ![Visualization type menu in Elastic showing options like Metric, Table, Bar horizontal, and Bar vertical stacked.](https://academy.hackthebox.com/storage/modules/211/visualization4.png)
    

---

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Elastic table configuration interface with options to add or drag-and-drop fields into Rows, Columns, and Metrics.](https://academy.hackthebox.com/storage/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Elastic Rows configuration for user.name.keyword, showing top 1000 values ranked by count of records in descending order.](https://academy.hackthebox.com/storage/modules/211/visualization6.png)

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Elastic table configuration with 'Top values of user.name.keyword' in Rows and options to add fields in Columns and Metrics.](https://academy.hackthebox.com/storage/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Elastic Metrics configuration with 'Count' function selected from options like Average, Median, and Sum.](https://academy.hackthebox.com/storage/modules/211/visualization8.png)

One final addition to the table is to include another "Rows" setting to show the machine where the failed logon attempt occurred. To do this, we will select the `host.hostname.keyword` field, which represents the computer reporting the failed logon attempt. This will allow us to display the hostname or machine name alongside the count of failed logon attempts, as shown in the image.

![Elastic table showing top values of user.name.keyword as 'anni' and host.hostname.keyword as 'WS001' with a count of records as 1.](https://academy.hackthebox.com/storage/modules/211/visualization31.png)

Now we can see three columns in the table, which contain the following information:

1. The disabled user whose credentials generated the failed logon attempt event.
    
2. The machine on which the logon attempt occurred.
    
3. The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).
    

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard.


# Successful RDP Logon related To Service Accounts

In this SIEM visualization example, we aim to create a visualization to monitor successful RDP logons specifically related to service accounts. Service account credentials are never used for RDP logons in corporate/real-world environments. We have been informed by the IT Operations department that all service accounts on the environment start with `svc-`.

The motivation for this visualization stems from the fact that service accounts often possess exceptionally high privileges. We need to keep a close eye on how service accounts are used.

Our visualization will be based on the following Windows event log.

- [4624: An account was successfully logged on](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)

Navigate to the bottom of this section and click on `Click here to spawn the target system!`.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

![Elastic Dashboards page with a 'Create dashboard' button, search bar, and a listed dashboard titled 'SOC-Alerts' with an edit option.](https://academy.hackthebox.com/storage/modules/211/visualization16.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

![Elastic dashboard interface with options to add a filter, select 'windows*' index, search field names, and choose 'Bar vertical stacked' visualization.](https://academy.hackthebox.com/storage/modules/211/visualization1.png)

There are five things for us to notice on this window:

1. A filter option that allows us to filter the data before creating a graph. In this case our goal is to display successful RDP logons specifically related to service accounts. We can use a filter to only consider event IDs that match `4624 – An account was successfully logged on`. In this case though, we should also take into account the logon type which should be `RemoteInteractive` (`winlog.logon.type` field). The following images demonstrates how we can specify such filters.
    
    ![Elastic filter editor with 'event.code' set to 'is 4624' and options to save or cancel.](https://academy.hackthebox.com/storage/modules/211/visualization38.png)
    
    ![Elastic filter editor with 'winlog.logon.type' set to 'is RemoteInteractive' and options to save or cancel.](https://academy.hackthebox.com/storage/modules/211/visualization39.png)
    
2. This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
    
3. This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. We are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.
    
    ![Elastic search interface with query 'user.' and available fields like related.user.keyword and user.name.keyword.](https://academy.hackthebox.com/storage/modules/211/visualization11.png)
    
4. Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.
    
    ![Elastic visualization type menu with options like Metric, Table, Bar horizontal, and Bar vertical stacked.](https://academy.hackthebox.com/storage/modules/211/visualization4.png)
    

---

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Table configuration interface with options to add or drag-and-drop fields into Rows, Columns, and Metrics sections.](https://academy.hackthebox.com/storage/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Rows configuration interface: Select user.name.keyword field, top 1000 values, ranked by count of records in descending order.](https://academy.hackthebox.com/storage/modules/211/visualization6.png)

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Table configuration: Rows set to top values of user.name.keyword, add fields to Columns and Metrics.](https://academy.hackthebox.com/storage/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Metrics selection interface: Choose 'Count' function for field.](https://academy.hackthebox.com/storage/modules/211/visualization8.png)

One final addition to the table is to include two more "Rows" settings to show the machine where the successful RDP logon attempt occurred and the machine that initiated the successful RDP logon attempt. To do this, we will select the `host.hostname.keyword` field that represents the computer reporting the successful RDP logon attempt and the `related.ip.keyword` field that represents the IP of the computer initiating the succsessful RDP logon attempt. This will allow us to display the involved machines alongside the count of successful logon attempts, as shown in the image.

![Rows configuration: Select host.hostname.keyword, top 1000 values, ranked by number of logins in descending order.](https://academy.hackthebox.com/storage/modules/211/visualization40.png)

![Rows configuration: Select related.ip.keyword, top 1000 values, ranked by number of logins in descending order.](https://academy.hackthebox.com/storage/modules/211/visualization41.png)

As discussed, we want to monitor successful RDP logons specifically related to service accounts, knowing for a fact that all service accounts of the environment start with `svc-`. So, to conclude our visualization we need to specify the following KQL query.

  SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts

```shell-session
user.name: svc-*
```

**Note**: As you can see we don't use the `.keyword` field in KQL queries.

![Elastic dashboard showing user logins: svc-sql1 connected to PKI, 2 logins.](https://academy.hackthebox.com/storage/modules/211/visualization43.png)

Now we can see four columns in the table, which contain the following information:

1. The service account whose credentials generated the successful RDP logon attempt event.
    
2. The machine on which the logon attempt occurred.
    
3. The IP of the machine that initiated the logon attempt.
    
4. The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).
    

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard.



# Users Added Or Removed From A Local Group

In this SIEM visualization example, we aim to create a visualization to monitor user additions or removals from the local "Administrators" group from March 5th 2023 to date.

Our visualization will be based on the following Windows event logs.

- [4732: A member was added to a security-enabled local group](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4732)
- [4733: A member was removed from a security-enabled local group](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4733)

Navigate to the bottom of this section and click on `Click here to spawn the target system!`.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard with SOC-Alerts listed, option to create or edit dashboards.](https://academy.hackthebox.com/storage/modules/211/visualization16.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

![Elastic dashboard: Add filter, select windows index, bar vertical stacked chart.](https://academy.hackthebox.com/storage/modules/211/visualization1.png)

There are five things for us to notice on this window:

1. A filter option that allows us to filter the data before creating a graph. In this case our goal is to display user additions or removals from the local "Administrators" group. We can use a filter to only consider event IDs that match `4732 – A member was added to a security-enabled local group` and `4733 – A member was removed from a security-enabled local group`. We can also use a filter to only consider 4732 and 4733 events where the local group is the "Administrators" one.
    
    ![Elastic dashboard filter: event.code is 4732 or 4733, group.name is administrators.](https://academy.hackthebox.com/storage/modules/211/visualization44.png)
    
2. This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
    
3. This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. We are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.
    
    ![Elastic dashboard: Filter event.code 4625, search user fields.](https://academy.hackthebox.com/storage/modules/211/visualization11.png)
    
4. Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.
    
    ![Visualization type menu: Bar vertical stacked selected.](https://academy.hackthebox.com/storage/modules/211/visualization4.png)
    

---

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Table configuration: Add fields to Rows, Columns, and Metrics.](https://academy.hackthebox.com/storage/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Rows configuration: Select user.name.keyword, top 1000 values, ranked by count of records in descending order.](https://academy.hackthebox.com/storage/modules/211/visualization6.png)

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Table configuration: Rows set to top values of user.name.keyword, add fields to Columns and Metrics.](https://academy.hackthebox.com/storage/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Metrics selection: Choose 'Count' function.](https://academy.hackthebox.com/storage/modules/211/visualization8.png)

One final addition to the table is to include some more "Rows" settings to enhance our understanding.

- Which user was added to or removed from the group? (`winlog.event_data.MemberSid.keyword` field)
    
- To which group was the addition or the removal performed? (double-checking that it is the "Administrators" one) (`group.name.keyword` field)
    
- Was the user added to or removed from the group? (`event.action.keyword` field)
    
- On which machine did the action occur? (`host.name.keyword` field)
    
    ![Table showing top values of user.name, winlog.event_data.MemberSid, group.name, event.action, host.name, with record counts.](https://academy.hackthebox.com/storage/modules/211/visualization46.png)
    

Click on "Save and return", and you will observe that the new visualization is added to the dashboard.

As discussed, we want to monitor user additions or removals from the local "Administrators" group _within a specific timeframe (March 5th 2023 to date)_.

We can narrow the scope of our visualization as follows.

![Dashboard showing failed logon attempts and RDP logon for service account, with options to edit lens and create drilldown.](https://academy.hackthebox.com/storage/modules/211/visualization47.png)

![Dashboard showing failed logon attempts and RDP logon for service account, with options to customize time range.](https://academy.hackthebox.com/storage/modules/211/visualization48.png)

![Dashboard with failed logon attempts and RDP logon, showing panel time range customization to March 5, 2023.](https://academy.hackthebox.com/storage/modules/211/visualization50.png)

Finally, let's click on the "Save" button so that all our edits persist.