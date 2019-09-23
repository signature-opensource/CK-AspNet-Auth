using CK.Text;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CodeCake
{
    public class AngularWorkspace
    {
        public NPMProject WorkspaceProject { get; }
        public IReadOnlyList<NPMProject> Projects { get; }
        public NormalizedPath OutputPath { get; }

        AngularWorkspace( NPMProject workspaceProject, IReadOnlyList<NPMProject> projects, NormalizedPath outputPath )
        {
            WorkspaceProject = workspaceProject;
            Projects = projects;
            OutputPath = outputPath;
        }

        public static AngularWorkspace Create( StandardGlobalInfo globalInfo, NormalizedPath path, NormalizedPath outputPath )
        {
            NormalizedPath packageJsonPath = path.AppendPart( "package.json" );
            NormalizedPath angularJsonPath = path.AppendPart( "angular.json" );

            JObject packageJson = JObject.Parse( File.ReadAllText( packageJsonPath ) );
            JObject angularJson = JObject.Parse( File.ReadAllText( angularJsonPath ) );
            if( !angularJson["private"].ToObject<bool>() ) throw new InvalidDataException( "A workspace project should be private." );
            string solutionName = packageJson["name"].ToString();
            List<string> names = angularJson["projects"].ToObject<JObject>().Properties().Select( p => p.Name ).ToList();
            List<NPMProject> projects = names.Select(
                p => NPMPublishedProject.Create(
                    globalInfo,
                    new NormalizedPath( angularJson["projects"][p]["root"].ToString() ),
                    outputPath.AppendPart( p )
                )
            ).ToList();
            return new AngularWorkspace( projects.Single( p => p.DirectoryPath == path ), projects, outputPath );
        }

        public void Pack()
        {
            foreach( var p in Projects )
            {
                if( p is NPMPublishedProject o )
                {
                    o.RunPack();
                }
            }
        }

        public void RunNpmCI()
        {
            foreach( var project in Projects )
            {
                project.RunNpmCi();
            }
        }

        public void RunClean()
        {
            foreach( var p in Projects )
            {
                p.RunClean();
            }
        }

        public void Build() => WorkspaceProject.RunBuild();

        public void Test()
        {
            foreach( var p in Projects )
            {
                p.RunTest( true );
            }
        }

    }
}
